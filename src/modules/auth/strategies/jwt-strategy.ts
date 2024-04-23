import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { LoginUserDto } from '../dto/login_user.dto';
import { UnauthorizedException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { User } from '../entities/user.entity';

export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private authService: AuthService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: `${process.env.JWT_SECRET}`,
    });
  }
  async validate(params: LoginUserDto): Promise<User> {
    const user = await this.authService.validateUser(params);
    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }
}
