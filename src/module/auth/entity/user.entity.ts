import {
    Column,
    CreateDateColumn,
    UpdateDateColumn,
    Entity,
    PrimaryGeneratedColumn,
} from 'typeorm';
import { Exclude } from 'class-transformer';
@Entity({ name: 'users' })
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Exclude()
    @Column({ nullable: true })
    githubId: string | null;

    @Exclude()
    @Column({ nullable: true })
    firebaseUid: string | null;

    @Column()
    firstName: string;

    @Column()
    lastName: string;

    @Column({ unique: true })
    email: string;

    @Exclude()
    @Column()
    password: string;

    @Exclude()
    @CreateDateColumn({ type: 'timestamp' })
    createdAt: Date;

    @Exclude()
    @UpdateDateColumn({ type: 'timestamp' })
    updatedAt: Date;

    @Column({ type: 'boolean', default: false })
    isAccountVerified: boolean;

    @Exclude()
    @Column({ type: 'boolean', default: false })
    isAccountBlocked: boolean;

    @Exclude()
    @Column({ type: 'int', default: 0 })
    failedLoginAttempts: number;

    @Exclude()
    @Column({ nullable: true })
    magicLinkToken: string | null;

    @Exclude()
    @Column({ type: 'timestamp', nullable: true })
    magicLinkTokenExpiration: Date | null;

    @Exclude()
    @Column({ type: 'text', nullable: true })
    refreshToken: string | null;

    @Exclude()
    @Column({ type: 'timestamp', nullable: true })
    refreshTokenExpiration: Date | null;

    @Exclude()
    @Column({ nullable: true })
    forgotPassword: string | null;

    @Exclude()
    @Column({ nullable: true })
    resetPassword: string | null;

    @Exclude()
    @Column({ nullable: true })
    avatarUrl: string | null;

    @Exclude()
    @Column({ type: 'text', nullable: true })
    otpCode: string | null;

    @Exclude()
    @Column({ type: 'boolean', default: false })
    isResetCodeVerified: boolean;

    @Exclude()
    @Column({ type: 'timestamp', nullable: true })
    otpExpiresAt: Date | null;

    @Exclude()
    @Column({ type: 'boolean', default: false })
    isEmailVerified: boolean;

    @Exclude()
    @Column({ nullable: true })
    githubProfileUrl: string | null;
}


