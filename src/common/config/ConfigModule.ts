import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService} from "@nestjs/config";
import { TypeOrmModule } from "@nestjs/typeorm";
@Module({
    imports: [  
        ConfigModule.forRoot({          
            isGlobal: true
        }),
        TypeOrmModule.forRootAsync({        
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (configService: ConfigService) => ({
                type: 'postgres',
                host: configService.get<string>('DATABASE_HOST'),
                port: configService.get<number>('DATABASE_PORT'),
                username: configService.get<string>('DATABASE_USERNAME'),
                password: configService.get<string>('DATABASE_PASSWORD'),
                database: configService.get<string>('DATABASE_NAME'),
                synchronize: true,
                autoLoadEntities: true,
            }),
        }),
    ],
    providers: [],
    exports: [],
})
export class AppConfigModule {}         