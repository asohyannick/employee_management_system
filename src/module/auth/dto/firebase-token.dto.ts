import { IsEmail, IsNotEmpty, IsString } from "class-validator";
export class FirebaseTokenIdDto {
    @IsNotEmpty({ message: "Token must be provided" })
    @IsString({ message: "Token cannot be empty" })
    token: string;
}
