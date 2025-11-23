import { IsNotEmpty, IsString } from "class-validator";
export class RefreshTokenDto {
    @IsNotEmpty({message: "Token must be provided"})
    @IsString({message: "Token cannot be empty"})
    token: string;
}

export class RevokeRefreshTokenDto {
    @IsNotEmpty({message: "User ID must be provided"})
    @IsString({message: "User ID cannot be empty"})
    userId: number;
}