import { MigrationInterface, QueryRunner } from 'typeorm';

export class CreateUsersTable1733600000000 implements MigrationInterface {
  name = 'CreateUsersTable1733600000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE "users" (
        "id" SERIAL PRIMARY KEY,
        "githubId" VARCHAR,
        "firebaseUid" VARCHAR,
        "firstName" VARCHAR NOT NULL,
        "lastName" VARCHAR NOT NULL,
        "email" VARCHAR NOT NULL UNIQUE,
        "password" VARCHAR NOT NULL,
        "createdAt" TIMESTAMP NOT NULL DEFAULT now(),
        "updatedAt" TIMESTAMP NOT NULL DEFAULT now(),
        "isAccountVerified" BOOLEAN NOT NULL DEFAULT false,
        "isAccountBlocked" BOOLEAN NOT NULL DEFAULT false,
        "failedLoginAttempts" INTEGER,
        "magicLinkToken" VARCHAR,
        "magicLinkTokenExpiration" TIMESTAMP,
        "refreshToken" TEXT,
        "refreshTokenExpiration" TIMESTAMP,
        "forgotPassword" VARCHAR,
        "resetPassword" VARCHAR,
        "avatarUrl" VARCHAR,
        "otpCode" TEXT,
        "isResetCodeVerified" BOOLEAN NOT NULL DEFAULT false,
        "otpExpiresAt" TIMESTAMP,
        "isEmailVerified" BOOLEAN NOT NULL DEFAULT false,
        "githubProfileUrl" VARCHAR
      );
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE "users"`);
  }
}
