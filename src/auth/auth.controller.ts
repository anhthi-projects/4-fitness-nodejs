import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signUpLocal(@Body() payload: AuthDto): Promise<Tokens> {
    return this.authService.signUpLocal(payload);
  }

  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signInLocal(@Body() payload: AuthDto): Promise<Tokens> {
    return this.authService.signInLocal(payload);
  }

  @UseGuards(AuthGuard('jwt')) // same name in access-token.strategy.ts
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@Req() req: Request) {
    const user = req.user;
    return this.authService.logout(user['sub']);
  }

  @UseGuards(AuthGuard('jwt-refresh')) // same name in refresh-token.strategy.ts
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshToken() {
    return this.authService.refreshToken();
  }
}
