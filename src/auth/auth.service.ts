import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  Injectable,
  NotFoundException,
  UnauthorizedException
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { compare, hash } from 'bcrypt';
import { PrismaService } from 'src/prisma.service';
import { CreateUserDto } from './types/auth.dto';

import { ConfigService } from '@nestjs/config';
import * as randomstring from 'randomstring';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) { }


  private async hashPassword(password: string): Promise<string> {
    return await hash(password, 12);
  }

  async createUser(data: CreateUserDto) {
    try {

      // Creating user in the database
      const user = await this.prisma.$transaction(async (transaction) => {
        const user = await transaction.user.create({
          data: {
            email: data.email,
            password: await this.hashPassword(data.password),
          },
          select: {
            id: true,
            email: true,
            createdAt: true,
            emailVerified: true,
          },
        });
        return user;
      });

      // Generating access and refresh tokens
      const { accessToken, refreshToken } = await this.getTokens(
        user.id,
        user.email,
      );

      return {
        accessToken: accessToken,
        refreshToken: refreshToken,
        user: user,
      };
    } catch (error) {
      if (
        error instanceof PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new BadRequestException('User with email already exists');
      }

      throw new HttpException(error.message, error.status || 500);
    }
  }

  async validateUser(email: string, password: string) {
    try {
      const user = await this.prisma.user.findUnique({
        where: {
          email: email,
        },
        select: {
          id: true,
          email: true,
          password: true,
          emailVerified: true,
        },
      });

      if (!user) {
        throw new NotFoundException("User with email doesn't exist");
      }

      if (!user.emailVerified) {
        throw new UnauthorizedException('User Email Not Verified');
      }

      const checkPassword = await compare(password, user.password);

      if (checkPassword) {
        const { accessToken, refreshToken } = await this.getTokens(
          user.id,
          user.email,
        );

        const userDetails = await this.prisma.user.findUnique({
          where: {
            id: user.id,
          },
          select: {
            id: true,
            email: true,
            emailVerified: true,
            createdAt: true,
          },
        });

        return {
          accessToken: accessToken,
          refreshToken: refreshToken,
          user: userDetails,
        };
      } else {
        throw new UnauthorizedException('Incorrect Password');
      }
    } catch (error) {
      throw new HttpException(error.message, error.status || 500);
    }
  }

  async deleteAccountByEmail(email: string, password: string) {
    try {
      const user = await this.prisma.user.findUnique({
        where: {
          email: email,
        },
        select: {
          id: true,
          email: true,
          password: true,
          emailVerified: true,
        },
      });

      if (!user) {
        throw new NotFoundException("User with email doesn't exist");
      }

      const checkPassword = await compare(password, user.password);

      if (checkPassword) {
        const deletedUser = await this.prisma.user.delete({
          where: {
            id: user.id,
          },
        });

        return deletedUser;
      } else {
        throw new UnauthorizedException('Incorrect Password');
      }
    } catch (error) {
      throw new HttpException(error.message, error.status || 500);
    }
  }

  async refreshTokens(
    userId: string,
    userEmail: string,
    requestRefreshToken: string,
  ) {
    try {
      const userRefreshTokens = await this.prisma.refreshToken.findMany({
        where: {
          userId: userId,
        },
      });

      if (!userRefreshTokens || userRefreshTokens.length === 0) {
        throw new ForbiddenException('Access Denied');
      }

      for (const userRefreshToken of userRefreshTokens) {
        if (userRefreshToken.token === requestRefreshToken) {
          const { accessToken, refreshToken } = await this.getTokens(
            userId,
            userEmail,
          );

          await this.logout(requestRefreshToken); // Clear used refresh token

          return {
            accessToken: accessToken,
            refreshToken: refreshToken,
          };
        }
      }

      throw new UnauthorizedException('Invalid Refresh Token');
    } catch (error) {
      throw new HttpException(error.message, error.status || 500);
    }
  }

  async logout(requestRefreshToken: string): Promise<boolean> {
    try {
      await this.prisma.refreshToken.delete({
        where: {
          token: requestRefreshToken,
        },
      });
      return true;
    } catch (error) {
      throw new HttpException('Failed to log out', error.status || 500);
    }
  }

  async getTokens(id: string, email: string) {
    const jwtPayload = {
      id: id,
      email: email,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
        expiresIn: '30d',
      }),
    ]);

    await this.prisma.refreshToken.create({
      data: {
        userId: id,
        token: refreshToken,
      },
    });

    return {
      accessToken: accessToken,
      refreshToken: refreshToken,
    };
  }

  private async generateOTP() {
    return randomstring.generate({
      length: 6,
      charset: 'numeric',
    });
  }
}
