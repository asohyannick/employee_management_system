import { Injectable } from "@nestjs/common";
import nodemailer from "nodemailer";
import SMTPTransport from "nodemailer/lib/smtp-transport";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class MailService {
    private transporter: nodemailer.Transporter<SMTPTransport.SentMessageInfo>;

    constructor(private configService: ConfigService) {
        const port = Number(this.configService.get<number>("EMAIL_PORT"));
        const secure = port === 465; // SSL for 465, STARTTLS for 587

        this.transporter = nodemailer.createTransport({
            host: this.configService.get<string>("EMAIL_HOST"),
            port,
            secure,
            auth: {
                user: this.configService.get<string>("EMAIL_USER"),
                pass: this.configService.get<string>("EMAIL_PASS"),
            },
            tls: {
                rejectUnauthorized: false, // prevents SSL validation errors
            },
        });
    }

    async sendOtpEmail(to: string, otp: string): Promise<void> {
        const subject = "Your OTP Verification Code";

        const html = `
            <p>Your verification code is:</p>
            <h2>${otp}</h2>
            <p>This code expires in 10 minutes.</p>
        `;

        await this.transporter.sendMail({
            from: this.configService.get<string>("EMAIL_FROM"),
            to,
            subject,
            html,
        });
    }
}

