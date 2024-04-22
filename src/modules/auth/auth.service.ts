import { BadRequestException, Injectable } from '@nestjs/common';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create_user.dto';
import { LoginUserDto } from './dto/login_user.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  // TODOD: refactoring code pel krouy
  async validateUser(params: LoginUserDto): Promise<User> {
    const { email, password } = params;
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) throw new BadRequestException('Please register');

    const isMatch: boolean = bcrypt.compareSync(password, user.password);

    if (!isMatch) throw new BadRequestException('Password does not match');

    return user;
  }

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

    const accessToken = await this.jwtService.signAsync({
      id: existingUser.id,
    });

    const refreshToken = await this.jwtService.signAsync(
      {
        id: existingUser.id,
      },
      { expiresIn: '7d' },
    );

    response.cookie('jwt', accessToken, { httpOnly: true });

    return { accessToken, refreshToken };
  }

  async logout(response: Response) {
    response.clearCookie('jwt');
    return { message: 'success' };
  }

  async refreshToken(params: LoginUserDto, response: Response) {
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

    const accessToken = await this.jwtService.signAsync({
      id: existingUser.id,
    });

    const refreshToken = await this.jwtService.signAsync(
      {
        id: existingUser.id,
      },
      { expiresIn: '7d' },
    );

    response.cookie('jwt', accessToken, { httpOnly: true });

    return { refreshToken /*  refreshToken */ };
  }
}
