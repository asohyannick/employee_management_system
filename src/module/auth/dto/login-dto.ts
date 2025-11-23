import { IsEmail, IsNotEmpty, IsString, Matches } from "class-validator";

export class LoginDto {
    @IsEmail()
    @IsNotEmpty()
    @IsString({ message: 'Email must be provided' })
    email: string;

    @IsNotEmpty()
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/, {
        message: 'Password must be minimum eight characters, at least one letter and one number'
    })
    @IsString({ message: 'Password must be provided' })
    password: string;
}