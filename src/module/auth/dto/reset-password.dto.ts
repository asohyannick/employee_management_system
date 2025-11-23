import { IsNotEmpty, IsString } from "class-validator";

export class ResetPasswordDto {
    @IsNotEmpty()
    @IsString({ message: "Password must be provided" })
    password: string;

    @IsNotEmpty()
    @IsString({ message: "Confirm Password must be provided" })
    confirmPassword: string;
}
