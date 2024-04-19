import {
  BadRequestException,
  Injectable,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create_user.dto';
import { LoginUserDto } from './dto/login_user.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  // TODOD: refactoring code pel krouy
  // async validateUser(params: CreateUserDto): Promise<User> {
  //   const { email, password } = params;
  //   const user = await this.userRepository.findOne({ where: { email } });
  //   if (!user) throw new BadRequestException('Please register');

  //   const isMatch: boolean = bcrypt.compareSync(password, user.password);

  //   if (!isMatch) throw new BadRequestException('Password does not match');

  //   return user;
  // }

  async register(params: CreateUserDto): Promise<User> {
    const { email, password } = params;
    const existingUser = await this.userRepository.findOne({
      where: { email },
    });

    if (existingUser) throw new BadRequestException('User already exist!');

    const hashedPassword = await bcrypt.hash(password, 12);

    return this.userRepository.save({
      ...params,
      password: hashedPassword,
    });
  }

  async login(params: LoginUserDto, response: Response) {
    const { email, password } = params;
    const existingUser = await this.userRepository.findOne({
      where: { email },
    });

    if (!existingUser) throw new BadRequestException('Please register');

    const isPasswordValid = await bcrypt.compare(
      password,
      (await existingUser).password,
    );

    if (!isPasswordValid) {
      throw new BadRequestException('Incorrect password');
    }

    const jwt = await this.jwtService.signAsync({ id: existingUser.id });

    response.cookie('jwt', jwt, { httpOnly: true });

    return jwt;
  }

  async getService(@Req() request: Request) {
    try {
      const cookie = request.cookies['jwt'];
      const data = await this.jwtService.verifyAsync(cookie);
      if (!data) throw new UnauthorizedException();

      const user = await this.userRepository.findOne({
        where: { id: data['id'] },
      });
      const { password, ...result } = user;

      return result;
    } catch {
      throw new UnauthorizedException();
    }
  }

  async logout(response: Response) {
    response.clearCookie('jwt');
    return { message: 'success' };
  }
}
