import { User } from 'src/users/user.schema';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import mongoose, { HydratedDocument } from 'mongoose';

export type TaskDocument = HydratedDocument<Task>;

@Schema({ timestamps: true })
export class Task {
  @Prop({ required: true })
  title: string;

  @Prop({ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true })
  userId: mongoose.Types.ObjectId;

  @Prop()
  description?: string;

  @Prop({
    default: 'planned',
    enum: ['planned', 'in_progress', 'completed', 'cancelled'],
  })
  status: 'planned' | 'in_progress' | 'completed' | 'cancelled';

  @Prop({ default: 'none', enum: ['none', 'low', 'medium', 'high', 'urgent'] })
  priority: 'none' | 'low' | 'medium' | 'high' | 'urgent';

  @Prop({ type: [String], default: [] })
  tags: string[];

  @Prop()
  category: string;

  @Prop({ type: Map, of: mongoose.Schema.Types.Mixed })
  customFields: Map<string, any>;

  @Prop([{ time: Date, message: String }])
  reminders: {
    time: Date;
    message: string;
  }[];

  @Prop({ default: false })
  repeat: boolean;

  @Prop({
    type: {
      frequency: {
        type: String,
        enum: ['daily', 'weekly', 'monthly', 'yearly'],
      },
      interval: Number,
      endDate: Date,
    },
  })
  repeatRule?: {
    frequency: 'daily' | 'weekly' | 'monthly' | 'yearly';
    interval: number;
    endDate?: Date;
  };

  @Prop([{ title: String, completed: { type: Boolean, default: false } }])
  subTasks: {
    title: string;
    completed: boolean;
  }[];
}

export const TaskSchema = SchemaFactory.createForClass(Task);
