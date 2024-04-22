import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { AuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('user')
export class UserController {
  authService: any;
  constructor(private readonly userService: UserService) {}

  @UseGuards(AuthGuard)
  @Get()
  async getUserById(@Param('id') id: string) {
    return this.userService.getServiceId(id);
  }
}
