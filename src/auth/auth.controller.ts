import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards
} from '@nestjs/common';
import { ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { AccessTokenGuard } from './guards/AccessTokenGuard';
import { RefreshTokenGuard } from './guards/RefreshTokenGuard';
import {
  CreateUserDto,
  LoginEmailDto,
} from './types/auth.dto';
import { errorResponse, successResponse } from './utils/response.utils';

@ApiTags('Auth')
@Controller({
  version: '1',
  path: 'auth',
})
export class AuthController {
  constructor(
    private authService: AuthService,
  ) { }

  private ACCESS_TOKEN_EXPIRATION_TIME = 15 * 60 * 1000; // 15 minutes in milliseconds
  private REFRESH_TOKEN_EXPIRATION_TIME = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds

  @ApiOperation({ summary: 'Create user with email and password' })
  @ApiBody({
    type: CreateUserDto,
  })
  @Post('/create-user')
  async createUser(
    @Body() createdUserDto: CreateUserDto,
    @Res() res: Response,
  ) {
    try {
      const { accessToken, refreshToken, user } =
        await this.authService.createUser(createdUserDto);

      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: this.ACCESS_TOKEN_EXPIRATION_TIME,
      });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: this.REFRESH_TOKEN_EXPIRATION_TIME,
      });

      return res.json(successResponse('User created successfully', user));
    } catch (error) {
      return res
        .status(500)
        .json(errorResponse('Error creating user', error.message));
    }
  }

  @ApiOperation({ summary: 'Log in user with email and password' })
  @ApiBody({
    type: LoginEmailDto,
  })
  @HttpCode(200)
  @Post('/login')
  async Login(
    @Body() { email, password }: LoginEmailDto,
    @Res() res: Response,
  ) {
    try {
      const { accessToken, refreshToken, user } =
        await this.authService.validateUser(email, password);

      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: this.ACCESS_TOKEN_EXPIRATION_TIME,
      });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: this.REFRESH_TOKEN_EXPIRATION_TIME,
      });

      return res.json(successResponse('User signed in successfully', user));
    } catch (error) {
      return res
        .status(500)
        .json(errorResponse('Error signing in user', error.message));
    }
  }

  @ApiOperation({ summary: 'Delete user and user account' })
  @ApiBody({
    type: LoginEmailDto,
  })
  @Delete('deleteUser')
  async deleteUser(
    @Body() { email, password }: LoginEmailDto,
    @Res() res: Response,
  ) {
    try {
      const deletedUser = await this.authService.deleteAccountByEmail(
        email,
        password,
      );
      return res.json(
        successResponse(
          'Deleted user and user account successfully',
          deletedUser,
        ),
      );
    } catch (error) {
      return res
        .status(500)
        .json(errorResponse('Error deleting user', error.message));
    }
  }

  @ApiOperation({ summary: 'Checks Authentication passing Access Token' })
  @UseGuards(AccessTokenGuard)
  @Get('check-auth')
  async checkAuth(@Req() req, @Res() res: Response) {
    try {
      if (req.user) {
        return res.json(successResponse('User authenticated', req.user));
      }
    } catch (error) {
      return res
        .status(500)
        .json(errorResponse('Error checking authentication', error.message));
    }
  }

  @ApiOperation({ summary: 'Creates new access token using Refresh Token' })
  @UseGuards(RefreshTokenGuard)
  @Get('refresh')
  async refreshTokens(@Req() req, @Res() res: Response) {
    try {
      const { accessToken, refreshToken } =
        await this.authService.refreshTokens(
          req.user.id,
          req.user.email,
          req.user.refreshToken,
        );

      res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: this.ACCESS_TOKEN_EXPIRATION_TIME,
      });

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: this.REFRESH_TOKEN_EXPIRATION_TIME,
      });

      return res.json(
        successResponse('Access token granted', {
          id: req.user.id,
          email: req.user.email,
        }),
      );
    } catch (error) {
      return res
        .status(500)
        .json(errorResponse('Error refreshing tokens', error.message));
    }
  }

  @ApiOperation({
    summary:
      'Remove Refresh Token to logout user, from getting new access tokens',
  })
  @UseGuards(RefreshTokenGuard)
  @Get('logout')
  async logout(@Req() req, @Res() res: Response) {
    try {
      await this.authService.logout(req.user.refreshToken);

      res.cookie('accessToken', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        expires: new Date(0),
      });

      res.cookie('refreshToken', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        expires: new Date(0),
      });

      return res.json(successResponse('User logged out', null));
    } catch (error) {
      return res
        .status(500)
        .json(errorResponse('Error logging out user', error.message));
    }
  }
}
