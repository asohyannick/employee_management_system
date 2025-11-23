import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class VerifyOtpDto {
    @IsString({ message: 'OTP must be provided' })
    @IsNotEmpty({ message: 'OTP cannot be empty' })
    otp: string;
}

export class ResendOtpDto {
    @IsEmail()
    @IsString({ message: 'Email must be provided' })
    @IsNotEmpty({ message: 'Email cannot be empty' })
    email: string;
}
