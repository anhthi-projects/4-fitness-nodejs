import { Injectable } from '@nestjs/common';

import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import { hasData } from 'src/utils';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async getTokens(userId: number, email: string) {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'at-secret',
          expiresIn: 60 * 15, // 15 mins
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email,
        },
        {
          secret: 'rt-secret',
          expiresIn: 60 * 60 * 24 * 7, // 1 week
        },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  async signUpLocal(payload: AuthDto): Promise<Tokens> {
    const hashedPassword = await hasData(payload.password);
    const newUser = await this.prisma.user.create({
      data: {
        name: 'Ben',
        email: payload.email,
        password: hashedPassword,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRefreshTokenToDb(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async updateRefreshTokenToDb(userId: number, refreshToken: string) {
    const hashedRefreshToken = await hasData(refreshToken);
    await this.prisma.user.update({
      data: {
        refreshToken: hashedRefreshToken,
      },
      where: {
        id: userId,
      },
    });
  }

  signInLocal() {}

  logout() {}

  refreshToken() {}
}
