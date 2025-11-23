import { IsEmail, IsNotEmpty, IsString } from "class-validator";

export class MagicLinkDto {
    @IsEmail()
    @IsNotEmpty({ message: 'Email cannot be empty' })
    @IsString({ message: 'Email must be provided' })
    email: string;
}

export class MagicLinkTokenDto {
    @IsNotEmpty({ message: 'Token cannot be empty' })
    @IsString({ message: 'Token must be provided' })
    token: string;
}