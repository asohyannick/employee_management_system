import { IsEmail, IsNotEmpty, IsString, Matches } from "class-validator";
export class ForgotPasswordDto {
    @IsNotEmpty()
    @IsEmail()
    @IsString({ message: "Email must be provided" })
    email: string;
}

export class ResetPasswordDto {
    @IsNotEmpty({ message: "New password cannot be empty" })
    @IsString({ message: "New password must be provided" })
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/, {
        message: "Password must be at least 8 characters long, contain at least one letter, one number, and one special character"
    })
    newPassword: string;
}   

export class VerifyForgotPasswordDto {
    @IsNotEmpty({ message: "OTP cannot be empty" })
    @IsString({message: "OTP must be provided" })
    otp: string;
}