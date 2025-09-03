import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Request,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { UserDocument } from 'src/users/user.schema';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { Response, Request as ExpressRequest } from 'express';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './jwt-auth.guard';

interface AuthenticatedRequest {
  user: UserDocument;
}

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private configService: ConfigService,
  ) {}

  private setAuthCookies(
    res: Response,
    accessToken: string,
    refreshToken: string,
  ) {
    const secure = this.configService.get<string>('NODE_ENV') === 'production';
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000, // 15 minutes
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure,
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });
  }

  @Post('register')
  async register(
    @Body() registerDto: RegisterDto,
    @Request() req: ExpressRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, refreshToken, userId, email } =
      await this.authService.register(
        registerDto,
        req.headers['user-agent'],
        req.ip,
      );

    this.setAuthCookies(res, accessToken, refreshToken);
    return { message: 'User registered successfully', userId, email };
  }

  @Post('login')
  async login(
    @Body() loginDto: LoginDto,
    @Request() req: ExpressRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { accessToken, refreshToken, userId, email } =
      await this.authService.login(loginDto, req.headers['user-agent'], req.ip);

    this.setAuthCookies(res, accessToken, refreshToken);
    return { message: 'User logged in successfully', userId, email };
  }

  @Post('refresh')
  async refresh(
    @Request() req: ExpressRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token provided');
    }

    const {
      accessToken,
      refreshToken: newRefreshToken,
      userId,
      email,
    } = await this.authService.refresh(
      refreshToken,
      req.headers['user-agent'],
      req.ip,
    );

    this.setAuthCookies(res, accessToken, newRefreshToken);
    return { message: 'Token refreshed successfully', userId, email };
  }

  @Post('logout')
  async logout(
    @Request() req: ExpressRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const refreshToken = req.cookies?.refreshToken;

    if (refreshToken) {
      await this.authService.logout(
        refreshToken,
        req.headers['user-agent'],
        req.ip,
      );
    }
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    return { message: 'User logged out successfully' };
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Request() req: ExpressRequest) {
    return this.authService.profile(req.cookies?.accessToken);
  }

  @UseGuards(JwtAuthGuard)
  @Get('sessions')
  async listSessions(@Request() req: AuthenticatedRequest) {
    return this.authService.listUserSessions(req.user._id.toString());
  }

  @UseGuards(JwtAuthGuard)
  @Delete('sessions/:sessionId')
  async revokeSession(
    @Request() req: AuthenticatedRequest,
    @Param('sessionId') sessionId: string,
  ) {
    await this.authService.logoutBySessionId(
      req.user._id.toString(),
      sessionId,
    );
    return { message: 'Session revoked successfully' };
  }
}
