import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { RtGuard } from 'src/common/guards';
import { GetCurrentUser, Public } from 'src/common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public() // prevent from using AtGuard
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signUpLocal(@Body() payload: AuthDto): Promise<Tokens> {
    return this.authService.signUpLocal(payload);
  }

  @Public() // prevent from using AtGuard
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signInLocal(@Body() payload: AuthDto): Promise<Tokens> {
    return this.authService.signInLocal(payload);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUser('sub') userId: number) {
    return this.authService.logout(userId);
  }

  @Public() // by pass AtGuard
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshToken(@GetCurrentUser() user: { sub: number; refreshToken: string }) {
    return this.authService.refreshToken(user.sub, user.refreshToken);
  }
}
