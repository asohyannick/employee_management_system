
import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';

export interface JwtPayload {
    userId: number;
    email: string;
    firstName: string;
    lastName: string;
    isEmailVerified?: boolean;
    isAccountBlocked?: boolean;
}

@Injectable()
export class JwtTokenService {
    private readonly JWT_SECRET_KEY: string;
    private readonly JWT_REFRESH_KEY: string;
    private readonly JWT_EXPIRATION: number;
    private readonly JWT_REFRESH_EXPIRATION: number;

    constructor(private readonly configService: ConfigService) {
        this.JWT_SECRET_KEY = this.configService.get<string>('JWT_SECRET_KEY')!;
        this.JWT_REFRESH_KEY = this.configService.get<string>('JWT_REFRESH_TOKEN')!;

        if (!this.JWT_SECRET_KEY || !this.JWT_REFRESH_KEY) {
            throw new UnauthorizedException('Missing JWT keys in environment variables');
        }
        this.JWT_EXPIRATION = Number(this.configService.get<string>('JWT_EXPIRATION_TIME') || 3600);
        this.JWT_REFRESH_EXPIRATION = Number(
            this.configService.get<string>('JWT_REFRESH_TOKEN_EXPIRATION_TIME') || 86400
        );
    }

    generateTokens(payload: JwtPayload): { accessToken: string; refreshToken: string } {
        const accessToken = jwt.sign(payload, this.JWT_SECRET_KEY, { expiresIn: this.JWT_EXPIRATION });
        const refreshToken = jwt.sign(payload, this.JWT_REFRESH_KEY, { expiresIn: this.JWT_REFRESH_EXPIRATION });

        return { accessToken, refreshToken };
    }

    verifyAccessToken(token: string): JwtPayload {
        try {
            return jwt.verify(token, this.JWT_SECRET_KEY) as JwtPayload;
        } catch (err) {
            throw new UnauthorizedException('Invalid access token');
        }
    }

    verifyRefreshToken(token: string): JwtPayload {
        try {
            return jwt.verify(token, this.JWT_REFRESH_KEY) as JwtPayload;
        } catch (err) {
            throw new UnauthorizedException('Invalid refresh token');
        }
    }
}
