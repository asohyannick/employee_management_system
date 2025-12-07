import { MigrationInterface, QueryRunner } from 'typeorm';

export class FixUserBooleansAndNullable1733602000000 implements MigrationInterface {
  name = 'FixUserBooleansAndNullable1733602000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      UPDATE "users" SET
        "isAccountVerified"     = COALESCE("isAccountVerified", false),
        "isAccountBlocked"      = COALESCE("isAccountBlocked", false),
        "isResetCodeVerified"   = COALESCE("isResetCodeVerified", false),
        "isEmailVerified"       = COALESCE("isEmailVerified", false),
        "failedLoginAttempts"   = COALESCE("failedLoginAttempts", 0)
    `);

    await queryRunner.query(`
      ALTER TABLE "users"
      ALTER COLUMN "isAccountVerified"   SET DEFAULT false,
      ALTER COLUMN "isAccountVerified"   SET NOT NULL,
      ALTER COLUMN "isAccountBlocked"    SET DEFAULT false,
      ALTER COLUMN "isAccountBlocked"    SET NOT NULL,
      ALTER COLUMN "isResetCodeVerified" SET DEFAULT false,
      ALTER COLUMN "isResetCodeVerified" SET NOT NULL,
      ALTER COLUMN "isEmailVerified"     SET DEFAULT false,
      ALTER COLUMN "isEmailVerified"     SET NOT NULL,
      ALTER COLUMN "failedLoginAttempts" SET DEFAULT 0,
      ALTER COLUMN "failedLoginAttempts" SET NOT NULL,
      ALTER COLUMN "otpCode"             DROP NOT NULL,
      ALTER COLUMN "otpExpiresAt"        DROP NOT NULL,
      ALTER COLUMN "githubProfileUrl"    DROP NOT NULL;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "users"
      ALTER COLUMN "isAccountVerified"   DROP DEFAULT,
      ALTER COLUMN "isAccountBlocked"    DROP DEFAULT,
      ALTER COLUMN "isResetCodeVerified" DROP DEFAULT,
      ALTER COLUMN "isEmailVerified"     DROP DEFAULT,
      ALTER COLUMN "failedLoginAttempts" DROP DEFAULT;
    `);
  }
}
