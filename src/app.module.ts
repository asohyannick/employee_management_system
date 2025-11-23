import { Module } from '@nestjs/common';
import { AppConfigModule } from './common/config/ConfigModule';
import { UserModule } from './module/auth/user.module';
@Module({
  imports: [
    AppConfigModule,
    UserModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule { }
