import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { TokenPayload } from './token-payload';

@Injectable()
export class TokenService {
  constructor(private jwtService: JwtService) {}

  generateAccessToken(userId: string, email: string): string {
    return this.jwtService.sign(
      { sub: userId, email, type: 'access' },
      { expiresIn: '1d' },
    );
  }

  generateRefreshToken(userId: string, email: string): string {
    return this.jwtService.sign(
      { sub: userId, email, type: 'refresh' },
      { expiresIn: '30d' },
    );
  }

  verifyToken(token: string): TokenPayload {
    return this.jwtService.verify<TokenPayload>(token);
  }
}
