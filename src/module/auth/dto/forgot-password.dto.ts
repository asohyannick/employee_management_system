import { IsEmail, IsNotEmpty, IsString, Matches } from "class-validator";
export class ForgotPasswordDto {
    @IsNotEmpty()
    @IsEmail()
    @IsString({ message: "Email must be provided" })
    email: string;
}
 

export class VerifyForgotPasswordDto {
    @IsNotEmpty({ message: "OTP cannot be empty" })
    @IsString({message: "OTP must be provided" })
    otp: string;
}