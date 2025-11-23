import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { ConfigModule } from '@nestjs/config';
import { User } from './entity/user.entity';
import { JwtTokenService } from '../../common/jwt/jwt.service';
import { MailService } from '../../common/utils/mailEmailService';
import { FirebaseConfigModule } from '../../common/config/firebaseConfig';
import { AppConfigModule } from '../../common/config/ConfigModule';
@Module({
    imports: [
        ConfigModule,
        TypeOrmModule.forFeature([User]),
        FirebaseConfigModule
    ],
    controllers: [UserController],
    providers: [
        UserService,
        JwtTokenService,
        MailService,
    ],
    exports: [
        UserService,
    ],

})
export class UserModule { }

