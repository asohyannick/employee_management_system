import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { Exclude } from 'class-transformer'
@Entity({ name: 'users' })
export class User {
    @PrimaryGeneratedColumn()
    id: number;

    @Exclude()
    @Column({ nullable: true })
    githubId: string;

    @Exclude()
    @Column({ nullable: true })
    firebaseUid: string;

    @Column()
    firstName: string;

    @Column()
    lastName: string;

    @Column({})
    email: string;

    @Exclude()
    @Column()
    password: string;

    @Exclude()
    @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP', onUpdate: 'CURRENT_TIMESTAMP' })
    createdAt: Date;

    @Exclude()
    @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP', onUpdate: 'CURRENT_TIMESTAMP' })
    updatedAt: Date;

    @Column({ nullable: true })
    isAccountVerified: boolean = false;

    @Exclude()
    @Column({ nullable: true })
    isAccountBlocked: boolean;

    @Exclude()
    @Column({ nullable: true })
    failedLoginAttempts: number;

    @Exclude()
    @Column({ nullable: true })
    magicLinkToken: string;

    @Exclude()
    @Column({ type: 'timestamp', nullable: true })
    magicLinkTokenExpiration: Date;

    @Exclude()
    @Column({ type: 'text', nullable: true})
    refreshToken: string | null;

    @Exclude()
    @Column({ nullable: true })
    refreshTokenExpiration: Date;

    @Exclude()
    @Column({ nullable: true })
    forgotPassword: string;

    @Exclude()
    @Column({ nullable: true })
    resetPassword: string;

    @Exclude()
    @Column({ nullable: true })
    avatarUrl: string;

    @Exclude()
    @Column({ type: 'text', nullable: true })
    otpCode: string | null;

    @Exclude()
    @Column({ nullable: true })
    isResetCodeVerified: boolean;

    @Exclude()
    @Column({ type: 'timestamp', nullable: true })
    otpExpiresAt: Date | null;

    @Exclude()
    @Column({ nullable: true })
    isEmailVerified: boolean;

    @Exclude()
    @Column({ nullable: true })
    githubProfileUrl: string;
}

