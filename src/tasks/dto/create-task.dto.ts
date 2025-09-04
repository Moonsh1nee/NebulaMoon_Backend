import { Type } from 'class-transformer';
import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsDate,
  IsEnum,
  IsArray,
  IsObject,
  IsBoolean,
  IsDateString,
  IsNumber,
  IsMongoId,
  ValidateNested,
} from 'class-validator';
import mongoose from 'mongoose';

class ReminderDto {
  @IsDateString()
  time: Date;

  @IsOptional()
  @IsString()
  message?: string;
}

class RepeatRuleDto {
  @IsEnum(['daily', 'weekly', 'monthly', 'yearly'])
  frequency: 'daily' | 'weekly' | 'monthly' | 'yearly';

  @IsNumber()
  interval: number;

  @IsOptional()
  @IsDateString()
  endDate?: Date;
}

class SubTaskDto {
  @IsString()
  title: string;

  @IsOptional()
  @IsBoolean()
  completed?: boolean;
}

export class CreateTaskDto {
  @IsString()
  @IsNotEmpty()
  title: string;

  @IsMongoId()
  userId: mongoose.Types.ObjectId;

  @IsString()
  @IsOptional()
  description?: string;

  @IsOptional()
  @IsEnum(['planned', 'in_progress', 'completed', 'cancelled'])
  status?: 'planned' | 'in_progress' | 'completed' | 'cancelled';

  @IsOptional()
  @IsEnum(['none', 'low', 'medium', 'high', 'urgent'])
  priority?: 'none' | 'low' | 'medium' | 'high' | 'urgent';

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @IsOptional()
  @IsString()
  category?: string;

  @IsOptional()
  customFields?: Record<string, any>;

  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => ReminderDto)
  reminders?: ReminderDto[];

  @IsOptional()
  @IsBoolean()
  repeat?: boolean;

  @IsOptional()
  @ValidateNested()
  @Type(() => RepeatRuleDto)
  repeatRule?: RepeatRuleDto;

  @IsOptional()
  @ValidateNested({ each: true })
  @Type(() => SubTaskDto)
  subTasks?: SubTaskDto[];
}
