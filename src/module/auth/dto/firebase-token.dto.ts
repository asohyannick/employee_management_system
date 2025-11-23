import { IsEmail, IsNotEmpty, IsString } from "class-validator";
export class FirebaseTokenIdDto {
    @IsNotEmpty({ message: "Token must be provided" })
    @IsString({ message: "Token cannot be empty" })
    token: string;
}

export class FirebaseUserDto {
    @IsNotEmpty({ message: "Firebase user ID must be provided" })
    @IsString({ message: "Firebase user ID must be a string" })
    firebaseUid: string;

    @IsEmail()
    @IsNotEmpty({ message: "Email must be provided" })
    email: string;

    @IsNotEmpty({ message: "First name must be provided" })
    firstName: string;

    @IsNotEmpty({ message: "Last name must be provided" })
    lastName: string;

    @IsNotEmpty({ message: "Firebase user must be provided" })
    firebaseUser: any;
}