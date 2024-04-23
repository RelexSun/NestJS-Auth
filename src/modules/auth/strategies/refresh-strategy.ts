import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { LoginUserDto } from '../dto/login_user.dto';
import { AuthService } from '../auth.service';
import { User } from '../entities/user.entity';

export class RefreshJwtStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromBodyField('refreshToken'),
      ignoreExpiration: false,
      secretOrKey: `${process.env.JWT_SECRET}`,
    });
  }

  async validate(params: LoginUserDto): Promise<User> {
    const user = await this.authService.validateUser(params);

    return user;
  }
}
