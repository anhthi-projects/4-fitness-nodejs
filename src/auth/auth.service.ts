import { ForbiddenException, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

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

  async signInLocal(payload: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: payload.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('User not found');
    }

    const passwordMatches = await bcrypt.compare(
      payload.password,
      user.password,
    );

    if (!passwordMatches) {
      throw new ForbiddenException('Username or password incorrect');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenToDb(user.id, tokens.refresh_token);
    return tokens;
  }

  logout(userId: number) {
    return this.prisma.user.update({
      data: {
        refreshToken: null,
      },
      where: {
        id: userId,
        refreshToken: {
          not: null,
        },
      },
    });
  }

  async refreshToken(userId: number, refreshToken: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.refreshToken) {
      throw new ForbiddenException('User not found');
    }

    const rtMatches = await bcrypt.compare(refreshToken, user.refreshToken);

    if (!rtMatches) {
      throw new ForbiddenException('Refresh token not matched');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRefreshTokenToDb(user.id, tokens.refresh_token);
    return tokens;
  }
}
