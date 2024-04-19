import { Body, Controller, Get, Post, Res, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create_user.dto';
import { LoginUserDto } from './dto/login_user.dto';
import { Response, Request } from 'express';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async signUp(@Body() createUserDto: CreateUserDto) {
    return this.authService.register(createUserDto);
  }

  @Post('login')
  async signIn(
    @Body() loginUser: LoginUserDto,
    @Res({ passthrough: true }) response: Response,
  ) {
    return this.authService.login(loginUser, response);
  }

  @Get('user')
  async getUser(@Req() request: Request) {
    return this.authService.getService(request);
  }

  @Post('logout')
  async signOut(@Res({ passthrough: true }) response: Response) {
    return this.authService.logout(response);
  }
}
