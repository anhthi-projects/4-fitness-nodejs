import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('local/signup')
  signUpLocal(@Body() payload: AuthDto): Promise<Tokens> {
    return this.authService.signUpLocal(payload);
  }

  @Post('local/signin')
  signInLocal() {
    this.authService.signInLocal();
  }

  @Post('logout')
  logout() {
    this.authService.logout();
  }

  @Post('refresh')
  refreshToken() {
    this.authService.refreshToken();
  }
}
