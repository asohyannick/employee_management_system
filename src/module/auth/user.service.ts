import { BadRequestException, Inject, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { Repository } from "typeorm";
import * as bcrypt from "bcryptjs";
import { MailService } from "../../common/utils/mailEmailService";
import { JwtTokenService } from "../../common/jwt/jwt.service";
import { ConfigService } from "@nestjs/config";
import { User } from "./entity/user.entity";
import { LoginDto } from "./dto/login-dto";
import { CreateUserDto } from "./dto/create-user.dto";
import * as admin from 'firebase-admin';
import axios from "axios";
import { Response } from "express";
import * as nodemailer from 'nodemailer';

@Injectable()
export class UserService {
    private transporter: nodemailer.Transporter;
    constructor(
        @InjectRepository(User)
        private userRepository: Repository<User>,
        private mailService: MailService,
        private jwtTokenService: JwtTokenService,
        @Inject('FIREBASE_ADMIN')
        private firebaseAdmin: admin.app.App,
        private configService: ConfigService
    ) {
        this.transporter = nodemailer.createTransport({
            host: this.configService.get<string>('EMAIL_HOST'),
            port: Number(this.configService.get<number>('EMAIL_PORT')),
            secure: false,
            auth: {
                user: this.configService.get<string>('EMAIL_USER'),
                pass: this.configService.get<string>('EMAIL_PASS'),
            }
        });
    }

    private generateOtp(): string {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    async updateRefreshToken(userId: number, refreshToken: string): Promise<void> {
        const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

        await this.userRepository.update(
            { id: userId },
            { refreshToken: hashedRefreshToken }
        );
    }

    async register(createUserDto: CreateUserDto, res: Response): Promise<User> {
        const existingUser = await this.userRepository.findOne({ where: { email: createUserDto.email } });
        if (existingUser) {
            throw new BadRequestException("Email already exists");
        }
        const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
        const newUser = this.userRepository.create({
            ...createUserDto,
            password: hashedPassword,
            isEmailVerified: false,
            isAccountBlocked: false,
        });

        await this.userRepository.save(newUser);


        const { accessToken, refreshToken } = this.jwtTokenService.generateTokens(
            {
                userId: newUser.id,
                email: newUser.email,
                firstName: newUser.firstName,
                lastName: newUser.lastName,
                isEmailVerified: newUser.isEmailVerified,
                isAccountBlocked: newUser.isAccountBlocked
            }
        )

        await this.updateRefreshToken(newUser.id, refreshToken)

        res.cookie('authToken', accessToken, {
            httpOnly: true,
            secure: this.configService.get<string>('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: Number(this.configService.get<number>('MAXAGE')),
        });
        const otp = this.generateOtp();
        newUser.otpCode = otp;
        newUser.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
        await this.userRepository.save(newUser);
        await this.mailService.sendOtpEmail(newUser.email, otp);
        return newUser;
    }

    async verifyOtp(otp: string): Promise<string> {
        const user = await this.userRepository.findOne({ where: { otpCode: otp } });

        if (!user) {
            throw new NotFoundException("User not found");
        }

        if (!user.otpCode || !user.otpExpiresAt) {
            throw new BadRequestException("OTP was not generated");
        }

        if (user.otpExpiresAt.getTime() < Date.now()) {
            throw new BadRequestException("OTP expired. Please request a new one.");
        }

        if (user.otpCode !== otp) {
            throw new BadRequestException("Invalid OTP");
        }

        user.isEmailVerified = true;
        user.otpCode = null;
        user.otpExpiresAt = null;

        await this.userRepository.save(user);

        return user.email;
    }

    async resendOtp(email: string): Promise<string> {
        const user = await this.userRepository.findOne({ where: { email } });

        if (!user) {
            throw new NotFoundException("User not found");
        }

        if (user.isEmailVerified) {
            throw new BadRequestException("Email already verified");
        }
        const otp = this.generateOtp();

        user.otpCode = otp;
        user.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
        await this.userRepository.save(user);
        await this.mailService.sendOtpEmail(user.email, otp);

        return user.email;
    }


    async login(loginDto: LoginDto, res: Response): Promise<User> {
        const MAX_FAILED_LOGIN_ATTEMPTS = 5;
        const user = await this.userRepository.findOne({ where: { email: loginDto.email } });
        if (!user) {
            throw new UnauthorizedException("User not found");
        }
        if (!user.isEmailVerified) {
            throw new UnauthorizedException("Account is not verified. Please verify your email first.");
        }
        if (user.isAccountBlocked) {
            throw new UnauthorizedException("Your account has been blocked. Please contact an administrator for assistance.");
        }
        const isPasswordValid = await bcrypt.compare(loginDto.password, user.password);
        if (!isPasswordValid) {
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;

            if (user.failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS) {
                user.isAccountBlocked = true;
            }
            await this.userRepository.save(user);
            const remainingAttempts = Math.max(0, MAX_FAILED_LOGIN_ATTEMPTS - user.failedLoginAttempts);
            throw new UnauthorizedException(`Invalid credentials. You have ${remainingAttempts} more attempt(s) before your account gets blocked.`);
        }
        user.failedLoginAttempts = 0;
        user.isAccountVerified = true;
        await this.userRepository.save(user);
        const { accessToken, refreshToken } = this.jwtTokenService.generateTokens(
            {
                userId: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                isEmailVerified: user.isEmailVerified,
                isAccountBlocked: user.isAccountBlocked,
            }
        )
        await this.updateRefreshToken(user.id, refreshToken);

        res.cookie('authToken', accessToken, {
            httpOnly: true,
            secure: this.configService.get<string>('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: Number(this.configService.get<number>('MAXAGE')),
        });
        return user;
    }

    async logout(userId: number, res: Response): Promise<User> {
        const user = await this.userRepository.findOne({ where: { id: userId } });
        if (!user) {
            throw new NotFoundException("User not found");
        }
        user.refreshToken = null;
        await this.userRepository.save(user);
        res.clearCookie('authToken');
        res.clearCookie('refreshToken');
        return user;
    }

    async fetchAllUsers(): Promise<User[]> {
        return this.userRepository.find();
    }

    async findById(id: number): Promise<User> {
        const user = await this.userRepository.findOne({ where: { id } });
        if (!user) {
            throw new NotFoundException("User not found");
        }
        return user;
    }

    async deleteUser(id: number): Promise<User> {
        const user = await this.userRepository.findOne({ where: { id } });
        if (!user) {
            throw new NotFoundException("User not found");
        }
        await this.userRepository.remove(user)
        return user;
    }

    async blockedAccount(id: number): Promise<User> {
        const user = await this.userRepository.findOne({ where: { id } });
        if (!user) {
            throw new NotFoundException("User not found");
        }
        if (user.isAccountBlocked) {
            throw new BadRequestException("Account is already blocked");
        }
        user.isAccountBlocked = true;
        await this.userRepository.save(user);
        return user;
    }

    async unBlockedAccount(id: number): Promise<User> {
        const user = await this.userRepository.findOne({ where: { id } });
        if (!user) {
            throw new NotFoundException("User not found");
        }
        if (!user.isAccountBlocked) {
            throw new BadRequestException("Account is already unblocked");
        }
        user.isAccountBlocked = false;
        await this.userRepository.save(user);
        return user;
    }

    async sendMagicLink(email: string): Promise<User> {
        const sanitizedEmail = email.toLowerCase().trim();
        const user = await this.userRepository.findOne({ where: { email: sanitizedEmail } });
        if (!user) {
            throw new NotFoundException("User not found");
        }
        const { accessToken, refreshToken } = this.jwtTokenService.generateTokens(
            {
                userId: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                isEmailVerified: user.isEmailVerified,
                isAccountBlocked: user.isAccountBlocked
            }
        )
        await this.updateRefreshToken(user.id, refreshToken);
        const token = accessToken;
        user.magicLinkToken = token;
        user.magicLinkTokenExpiration = new Date(Date.now() + 15 * 60 * 1000);
        await this.userRepository.save(user);
        const magicLink = `${this.configService.get<string>('ALLOWED_ORIGINS')}/magic-login?token=${token}`;

        await this.transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Your Magic Login Link',
            text: `Click the following link to log in: ${magicLink}\n\nThis link will expire in 15 minutes.`,
        });
        return user;
    }

    async loginWithMagicLink(token: string): Promise<{ user: User; accessToken: string; refreshToken: string }> {
        const user = await this.userRepository.findOne({ where: { magicLinkToken: token } });
        if (!user) throw new NotFoundException("Invalid or expired magic link");
        if (!user.magicLinkTokenExpiration || user.magicLinkTokenExpiration < new Date()) {
            throw new UnauthorizedException("Magic link has expired");
        }
        user.magicLinkToken = '';
        user.magicLinkTokenExpiration = new Date(0);
        const { accessToken, refreshToken } = this.jwtTokenService.generateTokens({
            userId: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            isEmailVerified: user.isEmailVerified,
            isAccountBlocked: user.isAccountBlocked
        });

        await this.updateRefreshToken(user.id, refreshToken);
        await this.userRepository.save(user);

        return { user, accessToken, refreshToken };
    }


    async forgotPassword(email: string): Promise<User> {
        const sanitizedEmail = email.toLowerCase().trim();
        const user = await this.userRepository.findOne({ where: { email: sanitizedEmail } });
        if (!user) {
            throw new NotFoundException("User not found");
        }
        const code = this.generateOtp();
        user.otpCode = code;
        const expires = new Date(Date.now() + 10 * 60 * 1000);
        user.otpExpiresAt = expires;
        await this.userRepository.save(user);
        await this.mailService.sendOtpEmail(user.email, code);
        return user;
    }

    async verifyForgotPasswordOTP(otp: string): Promise<User> {
        const user = await this.userRepository.findOne({ where: { otpCode: otp } });
        if (!user) {
            throw new NotFoundException("User not found");
        }
        if (!user.otpCode || !user.otpExpiresAt) {
            throw new BadRequestException("OTP was not generated");
        }
        if (user.otpExpiresAt.getTime() < Date.now()) {
            throw new BadRequestException("OTP expired. Please request a new one.");
        }
        if (user.otpCode !== otp) {
            throw new BadRequestException("Invalid OTP");
        }
        user.otpCode = null;
        user.otpExpiresAt = null;
        user.isResetCodeVerified = true;
        await this.userRepository.save(user);
        return user;
    }

    async resetPassword(newPassword: string): Promise<User> {
        const user = await this.userRepository.findOne({ where: { isResetCodeVerified: true } });
        if (!user) {
            throw new NotFoundException("No user found for password reset");
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.otpCode = null;
        user.otpExpiresAt = null;
        user.isResetCodeVerified = false;
        await this.userRepository.save(user);
        return user;
    }

    async refreshToken(refreshToken: string): Promise<User> {
        const user = await this.userRepository.findOne({ where: { refreshToken } });
        if (!user || !user.refreshToken) {
            throw new UnauthorizedException("Invalid refresh token");
        }
        const isValid = await bcrypt.compare(refreshToken, user.refreshToken);
        if (!isValid) {
            throw new UnauthorizedException("Invalid refresh token");
        }
        user.refreshToken = refreshToken;
        await this.userRepository.save(user);
        return user;
    }

    async revokeRefreshToken(userId: number): Promise<User> {
        const user = await this.userRepository.findOne({ where: { id: userId } });
        if (!user) {
            throw new UnauthorizedException("User not found");
        }
        user.refreshToken = null;
        await this.userRepository.save(user);
        return user;
    }

    async veirfyFirebaseToken(firebaseToken: string): Promise<User> {
        try {
            const decodedToken = await this.firebaseAdmin.auth().verifyIdToken(firebaseToken);
            const uid = decodedToken.uid;
            const user = await this.userRepository.findOne({ where: { firebaseUid: uid } });
            if (!user) {
                throw new NotFoundException("User not found");
            }
            return user;
        } catch (error) {
            throw new UnauthorizedException("Invalid Firebase token");
        }
    }

    async findOrCreateFirebaseUser(
        firebaseUid: string,
        email: string,
        firstName: string,
        lastName: string,
        firebaseUser: admin.auth.DecodedIdToken
    ): Promise<User> {
        let user = await this.userRepository.findOne({ where: { firebaseUid } });
        if (!user) {
            user = this.userRepository.create({
                firebaseUid,
                email: firebaseUser.email || email,
                firstName: firebaseUser.name ? firebaseUser.name.split(' ')[0] : firstName,
                lastName: firebaseUser.name ? firebaseUser.name.split(' ')[1] : lastName,
            });
            await this.userRepository.save(user);
        }
        return user;
    }

    async exchangeGithubCodeForToken(code: string): Promise<string> {
        const url = 'https://github.com/login/oauth/access_token';
        const { data } = await axios.post(
            url,
            {
                client_id: this.configService.get<string>('GITHUB_CLIENT_ID'),
                client_secret: this.configService.get<string>('GITHUB_CLIENT_SECRET'),
                code,
                redirect_uri: this.configService.get<string>('GITHUB_REDIRECT_URI'),
            },
            { headers: { Accept: 'application/json' } },
        );

        if (!data.access_token) {
            throw new UnauthorizedException('Failed to exchange code for access token');
        }

        return data.access_token;
    }

    async fetchGitHubUserProfile(accessToken: string): Promise<any> {
        const { data } = await axios.get('https://api.github.com/user', {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        return data;
    }

    async findOrCreateGithubUser(githubProfile: any): Promise<User> {
        let user = await this.userRepository.findOne({ where: { githubId: githubProfile.id.toString() } });

        if (!user) {
            user = this.userRepository.create({
                githubId: githubProfile.id.toString(),
                email: githubProfile.email,
                firstName: githubProfile.name ? githubProfile.name.split(' ')[0] : 'GitHubUser',
                lastName: githubProfile.name ? githubProfile.name.split(' ')[1] : '',
                avatarUrl: githubProfile.avatar_url,
                githubProfileUrl: githubProfile.html_url,
            });
            await this.userRepository.save(user);
        }

        return user;
    }

    async loginWithGithub(code: string, res: any): Promise<User> {
        const githubAccessToken = await this.exchangeGithubCodeForToken(code);
        const githubProfile = await this.fetchGitHubUserProfile(githubAccessToken);
        const user = await this.findOrCreateGithubUser(githubProfile);
        const { accessToken, refreshToken } = this.jwtTokenService.generateTokens(
            {
                userId: user.id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                isEmailVerified: user.isEmailVerified,
                isAccountBlocked: user.isAccountBlocked
            }
        );
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: this.configService.get<string>('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: this.configService.get<number>('MAXAGE'),
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: this.configService.get<string>('NODE_ENV') === 'production',
            sameSite: 'strict',
            maxAge: this.configService.get<number>('MAXAGE'),
        });

        return user;
    }
}