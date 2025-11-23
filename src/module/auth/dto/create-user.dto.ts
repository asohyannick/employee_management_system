import { IsEmail, isEmail, IsNotEmpty, IsString, Matches } from 'class-validator'
export class CreateUserDto {

    @IsNotEmpty()
    @IsString({ message: 'First name must be provided' })
    firstName: string;

    @IsNotEmpty()
    @IsString({ message: 'Last name must be provided' })
    lastName: string;

    @IsNotEmpty()
    @IsString({ message: 'Email must be provided' })
    @IsEmail()
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/, {
        message: 'Password must be minimum eight characters, at least one letter and one number'
    })
    email: string;

    @IsNotEmpty()
    @IsString({ message: 'Password must be provided' })
    password: string;

}