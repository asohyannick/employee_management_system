import { IsNotEmpty, Matches, ValidateIf, Validate, ValidatorConstraint, ValidatorConstraintInterface, ValidationArguments } from "class-validator";
@ValidatorConstraint({ name: "MatchPasswords", async: false })
export class MatchPasswords implements ValidatorConstraintInterface {
    validate(confirmPassword: any, args: ValidationArguments) {
        const object = args.object as any;
        return object.newPassword === confirmPassword;
    }

    defaultMessage(args: ValidationArguments) {
        return "Confirm Password does not match New Password";
    }
}

export class ResetPasswordDto {
    @IsNotEmpty({ message: "Password must be provided" })
    @ValidateIf((o) => o.newPassword)
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/, {
        message:
            "Password must be at least 8 characters long, contain at least one letter, one number, and one special character",
    })
    newPassword: string;

    @IsNotEmpty({ message: "Confirm Password must be provided" })
    @ValidateIf((o) => o.confirmPassword)
    @Matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/, {
        message:
            "Confirm Password must be at least 8 characters long, contain at least one letter, one number, and one special character",
    })
    @Validate(MatchPasswords)
    confirmPassword: string;
}

