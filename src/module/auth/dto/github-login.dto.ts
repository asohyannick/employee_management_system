import { IsNotEmpty, IsString } from "class-validator";
export class GithubLoginDto {
    @IsString({message: "Github auth code must be provided"})
    @IsNotEmpty({message: "Github auth code must be provided"})
    code: string;
}