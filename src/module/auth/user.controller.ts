import {
  Controller,
  Post,
  Get,
  Patch,
  Delete,
  Body,
  Param,
  Res,
  HttpCode,
  HttpStatus,
  Query,
} from '@nestjs/common';
import { UserService } from './user.service';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiQuery, ApiParam } from '@nestjs/swagger';
import type { Response } from 'express';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDto } from './dto/login-dto';
import { User } from './entity/user.entity';
import { ResendOtpDto, VerifyOtpDto } from './dto/verify-otp';
import { MagicLinkDto, MagicLinkTokenDto } from './dto/magic-link.dto';
import { ForgotPasswordDto, VerifyForgotPasswordDto } from './dto/forgot-password.dto';
import { RefreshTokenDto, RevokeRefreshTokenDto } from './dto/refresh-token.dto';
import { FirebaseTokenIdDto } from './dto/firebase-token.dto';
import { GithubLoginDto } from './dto/github-login.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
@ApiTags('Authentication & User Management Endpoints')
@Controller('auth')
export class UserController {
  constructor(private readonly userService: UserService) { }

  // ---------------- Registration ----------------
  @Post('register')
  @ApiOperation({ summary: 'Register a new user' })
  @ApiResponse({ status: 201, description: 'User successfully registered', type: User })
  @ApiResponse({ status: 400, description: 'Email already exists' })
  @ApiBody({ type: CreateUserDto })
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() createUserDto: CreateUserDto, @Res({ passthrough: true }) res: Response) {
    const data = await this.userService.register(createUserDto, res);
    return { message: 'User registered successfully. Please verify your email.', data };
  }

  // ---------------- OTP Verification ----------------
  @Post('verify-otp')
  @ApiOperation({ summary: 'Verify OTP for user email' })
  @ApiResponse({ status: 200, description: 'OTP verified successfully', type: String })
  @ApiResponse({ status: 400, description: 'Invalid or expired OTP' })
  @ApiQuery({ name: 'userId', required: true, type: Number })
  @ApiQuery({ name: 'otp', required: true, type: String })
  @HttpCode(HttpStatus.OK)
  async verifyOtp(@Body() verifyOtp: VerifyOtpDto) {
    const data = await this.userService.verifyOtp(verifyOtp.otp);
    return { message: 'OTP verified successfully.', data };
  }

  @Post('resend-otp')
  @ApiOperation({ summary: 'Resend OTP email to user' })
  @ApiResponse({ status: 200, description: 'OTP resent successfully', type: String })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiQuery({ name: 'email', required: true, type: String })
  async resendOtp(@Body() resendOtp: ResendOtpDto) {
    const data = await this.userService.resendOtp(resendOtp.email);
    return { message: 'OTP resent successfully.', data };
  }

  // ---------------- Login / Logout ----------------
  @Post('login')
  @ApiOperation({ summary: 'Login user with email & password' })
  @ApiResponse({ status: 200, description: 'User successfully logged in', type: User })
  @ApiResponse({ status: 401, description: 'Invalid credentials or account blocked' })
  @ApiBody({ type: LoginDto })
  async login(@Body() loginDto: LoginDto, @Res({ passthrough: true }) res: Response) {
    const data = await this.userService.login(loginDto, res);
    return { message: 'User successfully logged in.', data };
  }

  @Post('logout/:userId')
  @ApiOperation({ summary: 'Logout user and clear cookies' })
  @ApiResponse({ status: 200, description: 'User successfully logged out', type: User })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiParam({ name: 'userId', required: true, type: Number })
  async logout(@Param('userId') userId: number, @Res({ passthrough: true }) res: Response) {
    const data = await this.userService.logout(userId, res);
    return { message: 'User successfully logged out.', data };
  }

  // ---------------- Magic Link ----------------
  @Post('send-magic-link')
  @ApiOperation({ summary: 'Send magic login link to user email' })
  @ApiResponse({ status: 200, description: 'Magic link sent successfully', type: User })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiBody({ type: MagicLinkDto })
  async sendMagicLink(@Body() magicLinkDto: MagicLinkDto) {
    const link = await this.userService.sendMagicLink(magicLinkDto.email);
    return { message: 'Magic link sent successfully.', link };
  }

  @Post('login-with-magic-link')
  @ApiOperation({ summary: 'Login user using magic link token' })
  @ApiResponse({ status: 200, description: 'User successfully logged in with magic link' })
  @ApiResponse({ status: 401, description: 'Magic link expired or invalid' })
  @ApiBody({ type: MagicLinkTokenDto })
  async loginWithMagicLink(@Body() token: MagicLinkTokenDto) {
    const tokenLink = await this.userService.loginWithMagicLink(token.token);
    return { message: 'User successfully logged in with magic link.', tokenLink };
  }

  // ---------------- Password Reset ----------------
  @Post('forgot-password')
  @ApiOperation({ summary: 'Request OTP for password reset' })
  @ApiResponse({ status: 200, description: 'OTP sent successfully', type: User })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiQuery({ name: 'email', required: true, type: String })
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() email: ForgotPasswordDto) {
    const forgotPassword = await this.userService.forgotPassword(email.email);
    return { message: "OTP sent successfully.", forgotPassword };
  }

  @Post('verify-forgot-password-otp')
  @ApiOperation({ summary: 'Verify OTP for password reset' })
  @ApiResponse({ status: 200, description: 'OTP verified successfully', type: User })
  @ApiResponse({ status: 400, description: 'Invalid or expired OTP' })
  @ApiQuery({ name: 'otp', required: true, type: String })
  @HttpCode(HttpStatus.OK)
  async verifyForgotPasswordOtp(@Body() verifyOTP: VerifyForgotPasswordDto) {
    const verifyDto = await this.userService.verifyForgotPasswordOTP(verifyOTP.otp)
    return { message: "OTP has been verified successfully", verifyDto }
  }

  @Post('reset-password')
  @ApiOperation({ summary: 'Reset user password after OTP verification' })
  @ApiResponse({ status: 200, description: 'Password reset successfully', type: User })
  @ApiResponse({ status: 404, description: 'No user found for password reset' })
  @ApiBody({ type: ResetPasswordDto })
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() password: ResetPasswordDto) {
    const resetPassword = await this.userService.resetPassword(password.newPassword)
    return { message: "Password has been reset successfully", resetPassword };
  }

  // ---------------- Refresh / Revoke Token ----------------
  @Post('refresh-token')
  @ApiOperation({ summary: 'Refresh JWT using refresh token' })
  @ApiResponse({ status: 200, description: 'Refresh token valid', type: User })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  @ApiBody({ type: RefreshTokenDto })
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Body() refreshToken: RefreshTokenDto) {
    const token = await this.userService.refreshToken(refreshToken.token);
    return { message: "RefreshToken has been generated successfully", token };
  }

  @Post('revoke-refresh-token/:userId')
  @ApiOperation({ summary: 'Revoke refresh token for user' })
  @ApiResponse({ status: 200, description: 'Refresh token revoked', type: User })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiParam({ name: 'userId', required: true, type: Number })
  @HttpCode(HttpStatus.OK)
  async revokeRefreshToken(@Param('userId') userId: RevokeRefreshTokenDto) {
    const revokeToken = await this.userService.revokeRefreshToken(userId.userId)
    return { message: "RefreshToken has been revoked successfully!", revokeToken }
  }

  // ---------------- Firebase ----------------
  @Post('verify-firebase-token')
  @ApiOperation({ summary: 'Verify Firebase token and return user' })
  @ApiResponse({ status: 200, description: 'Firebase token valid', type: User })
  @ApiResponse({ status: 401, description: 'Invalid Firebase token' })
  @ApiBody({ type: FirebaseTokenIdDto })
  @HttpCode(HttpStatus.OK)
  async verifyFirebaseToken(@Body() firebaseTokenDto: FirebaseTokenIdDto) {
    const firebaseToken = await this.userService.veirfyFirebaseToken(firebaseTokenDto.token)
    return { message: "Firebase Token ID has been verified successfully!", firebaseToken }
  }

  @Post('firebase-login')
  @ApiOperation({ summary: 'Find or create a Firebase user' })
  @ApiResponse({ status: 200, description: 'Firebase user found or created', type: User })
  @ApiBody({ description: 'Decoded Firebase token payload', type: Object })
  @HttpCode(HttpStatus.OK)
  async findOrCreateFirebaseUser(@Body() firebaseUser: any
  ) {
    const createorFetchFirebaseUser = await this.userService.findOrCreateFirebaseUser(
      firebaseUser.email,
      firebaseUser.firebaseUid,
      firebaseUser.firstName,
      firebaseUser.lastName,
      firebaseUser.firebaseUser
    );
    return { message: "Firebase user has been found or created successfully!", createorFetchFirebaseUser };
  }

  // ---------------- GitHub OAuth ----------------
  @Get('github/callback')
  @ApiOperation({ summary: 'Login user with GitHub OAuth' })
  @ApiResponse({ status: 200, description: 'User successfully logged in with GitHub', type: User })
  @ApiBody({ description: 'GitHub OAuth code', type: String })
  @HttpCode(HttpStatus.OK)
  async loginWithGithub(@Query('code') code: string, @Res({ passthrough: true }) res: Response) {
    const result = await this.userService.loginWithGithub(code, res)
      return res.redirect("http://localhost:3000/success"); 
  }

  // ---------------- User Management ----------------
  @Get('fetch-users')
  @ApiOperation({ summary: 'Get all users' })
  @ApiResponse({ status: 200, description: 'List of users', type: [User] })
  @HttpCode(HttpStatus.OK)
  async fetchAllUsers() {
    const users = await this.userService.fetchAllUsers();
    return { message: "Users have been fetched successfully!", users };
  }

  @Get('fetch-user/:id')
  @ApiOperation({ summary: 'Get a user by ID' })
  @ApiResponse({ status: 200, description: 'User found', type: User })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiParam({ name: 'id', required: true, type: Number })
  async findById(@Param('id') id: number) {
    const user = await this.userService.findById(id);
    return { message: "User has been fetched successfully!", user };
  }

  @Delete('delete-user/:id')
  @ApiOperation({ summary: 'Delete a user by ID' })
  @ApiResponse({ status: 200, description: 'User deleted', type: User })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiParam({ name: 'id', required: true, type: Number })
  async deleteUser(@Param('id') id: number) {
    const user = await this.userService.deleteUser(id);
    return { message: "User has been deleted successfully!", user };
  }

  @Patch('block-account/:id')
  @ApiOperation({ summary: 'Block a user account' })
  @ApiResponse({ status: 200, description: 'User account blocked', type: User })
  @ApiResponse({ status: 400, description: 'Account already blocked' })
  @ApiParam({ name: 'id', required: true, type: Number })
  async blockAccount(@Param('id') id: number) {
    const user = await this.userService.blockedAccount(id);
    return { message: "User account has been blocked successfully!", user };
  }

  @Patch('unblock-account/:id')
  @ApiOperation({ summary: 'Unblock a user account' })
  @ApiResponse({ status: 200, description: 'User account unblocked', type: User })
  @ApiResponse({ status: 400, description: 'Account already unblocked' })
  @ApiParam({ name: 'id', required: true, type: Number })
  async unblockAccount(@Param('id') id: number) {
    const user = await this.userService.unBlockedAccount(id);
    return { message: "User account has been unblocked successfully!", user };
  }
}
