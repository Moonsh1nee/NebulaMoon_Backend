import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Types } from 'mongoose';

export type SessionDocument = HydratedDocument<Session>;

@Schema({ timestamps: true })
export class Session {
  @Prop({ type: Types.ObjectId, ref: 'User', required: true })
  userId: Types.ObjectId;

  @Prop({ required: true })
  refreshTokenHash: string;

  @Prop()
  userAgent?: string;

  @Prop()
  ip?: string;

  @Prop()
  deviceName?: string;

  @Prop()
  browser?: string;

  @Prop()
  os?: string;

  @Prop()
  platform?: string;

  @Prop({ default: false, index: true })
  revoked: boolean;

  @Prop({ type: Date, index: { expireAfterSeconds: 60 * 60 * 24 * 30 } })
  revokedAt?: Date;

  @Prop({ default: Date.now })
  lastUsedAt?: Date;
}

export const SessionSchema = SchemaFactory.createForClass(Session);

SessionSchema.index({ userId: 1, revoked: 1, createdAt: 1 });
SessionSchema.index({ userId: 1, userAgent: 1, ip: 1, revoked: 1 });
