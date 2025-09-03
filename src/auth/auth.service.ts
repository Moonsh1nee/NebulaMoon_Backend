import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { User, UserDocument } from '../users/user.schema';
import * as bcrypt from 'bcrypt';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Session, SessionDocument } from './session.schema';
import { TokenService } from './token.service';
import { TokenPayload } from './token-payload';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    @InjectModel(Session.name) private sessionModel: Model<SessionDocument>,
    private tokenService: TokenService,
  ) {}

  async register(registerDto: RegisterDto, userAgent?: string, ip?: string) {
    const { email, password, name } = registerDto;

    const existingUser = await this.userModel.findOne({ email });
    if (existingUser) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await this.userModel.create({
      email,
      password: hashedPassword,
      name,
    });

    const accessToken = this.tokenService.generateAccessToken(
      newUser._id.toString(),
      newUser.email,
    );
    const refreshToken = this.tokenService.generateRefreshToken(
      newUser._id.toString(),
      newUser.email,
    );
    await this.createSession(
      newUser._id.toString(),
      refreshToken,
      userAgent,
      ip,
    );

    return {
      accessToken,
      refreshToken,
      userId: newUser._id.toString(),
      email: newUser.email,
    };
  }

  async login(loginDto: LoginDto, userAgent?: string, ip?: string) {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const accessToken = this.tokenService.generateAccessToken(
      user._id.toString(),
      user.email,
    );
    const refreshToken = this.tokenService.generateRefreshToken(
      user._id.toString(),
      user.email,
    );

    const existingSession = await this.sessionModel.findOne({
      userId: user._id,
      userAgent,
      ip,
      revoked: false,
    });

    if (existingSession) {
      await this.updateSessionToken(
        existingSession._id.toString(),
        refreshToken,
        userAgent,
        ip,
      );
    } else {
      const revokedSession = await this.sessionModel.findOne({
        userId: user._id,
        userAgent,
        ip,
        revoked: true,
      });

      if (revokedSession) {
        revokedSession.revokedAt = new Date();
        await revokedSession.save();
      }

      await this.createSession(
        user._id.toString(),
        refreshToken,
        userAgent,
        ip,
      );
    }

    return {
      accessToken,
      refreshToken,
      userId: user._id.toString(),
      email: user.email,
    };
  }

  async refresh(refreshToken: string, userAgent?: string, ip?: string) {
    this.logger.log(
      'Refreshing token for userAgent: ' + userAgent + ', ip: ' + ip,
    );

    let payload: TokenPayload;
    try {
      payload = this.tokenService.verifyToken(refreshToken);
    } catch (error) {
      this.logger.warn(`Invalid refresh token: ${error.message}`);
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (payload.type !== 'refresh') {
      this.logger.warn('Token type is not refresh');
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.userModel.findById(payload.sub);
    if (!user) {
      this.logger.warn(`User not found for ID: ${payload.sub}`);
      throw new UnauthorizedException('User not found');
    }

    const session = await this.findValidSession(
      user._id.toString(),
      refreshToken,
      userAgent,
      ip,
    );
    if (!session) {
      this.logger.warn(`No valid session found for user: ${user._id}`);
      throw new UnauthorizedException('Session not found or revoked');
    }

    const newAccessToken = this.tokenService.generateAccessToken(
      user._id.toString(),
      user.email,
    );
    const newRefreshToken = this.tokenService.generateRefreshToken(
      user._id.toString(),
      user.email,
    );

    await this.updateSessionToken(
      session._id.toString(),
      newRefreshToken,
      userAgent,
      ip,
    );

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      userId: user._id.toString(),
      email: user.email,
    };
  }

  async logout(refreshToken: string, userAgent?: string, ip?: string) {
    try {
      const payload = this.tokenService.verifyToken(refreshToken);
      const session = await this.findValidSession(
        payload.sub,
        refreshToken,
        userAgent,
        ip,
      );
      if (session) {
        await this.revokeSession(session._id.toString());
      }
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async profile(accessToken: string) {
    const payload = this.tokenService.verifyToken(accessToken);
    const user = await this.userModel.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    return {
      userId: user._id.toString(),
      email: user.email,
    };
  }

  async logoutBySessionId(userId: string, sessionId: string) {
    const session = await this.sessionModel.findOne({
      _id: new Types.ObjectId(sessionId),
      userId: new Types.ObjectId(userId),
    });
    if (!session) {
      throw new UnauthorizedException('Session not found');
    }

    session.revoked = true;
    session.revokedAt = new Date();
    await session.save();
  }

  async listUserSessions(userId: string) {
    const sessions = await this.sessionModel
      .find({ userId: new Types.ObjectId(userId) })
      .sort({ createdAt: -1 })
      .lean();
    return sessions.map((s) => ({
      sessionId: s._id.toString(),
      userAgent: s.userAgent,
      ip: s.ip,
      revoked: s.revoked,
    }));
  }

  async validateUser(id: string) {
    return this.userModel.findById(id);
  }

  // Session helpers
  private async createSession(
    userId: string,
    refreshToken: string,
    userAgent?: string,
    ip?: string,
  ) {
    const hash = await bcrypt.hash(refreshToken, 10);
    return this.sessionModel.create({
      userId: new Types.ObjectId(userId),
      refreshTokenHash: hash,
      userAgent,
      ip,
    });
  }

  private async findValidSession(
    userId: string,
    refreshToken: string,
    userAgent?: string,
    ip?: string,
  ) {
    const session = await this.sessionModel.find({
      userId: new Types.ObjectId(userId),
      revoked: false,
      userAgent,
      ip,
    });
    for (const s of session) {
      if (await bcrypt.compare(refreshToken, s.refreshTokenHash)) {
        return s;
      }
    }
    return null;
  }

  private async updateSessionToken(
    sessionId: string,
    newRefreshToken: string,
    userAgent?: string,
    ip?: string,
  ) {
    const hash = await bcrypt.hash(newRefreshToken, 10);
    await this.sessionModel.findByIdAndUpdate(
      sessionId,
      {
        refreshTokenHash: hash,
        userAgent,
        ip,
        updatedAt: new Date(),
      },
      { new: true },
    );
  }

  private async revokeSession(sessionId: string) {
    await this.sessionModel.findByIdAndUpdate(sessionId, {
      revoked: true,
      revokedAt: new Date(),
    });
  }
}
