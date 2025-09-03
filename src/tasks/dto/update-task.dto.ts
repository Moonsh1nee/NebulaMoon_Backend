import {
  IsString,
  IsOptional,
  IsDate,
  IsEnum,
  IsArray,
  IsObject,
} from 'class-validator';

export class UpdateTaskDto {
  @IsString()
  @IsOptional()
  title?: string;

  @IsString()
  @IsOptional()
  categoryId?: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsDate()
  @IsOptional()
  dueDate?: Date;

  @IsEnum(['low', 'medium', 'high'])
  @IsOptional()
  priority?: string;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  tags?: string[];

  @IsObject()
  @IsOptional()
  recurrence?: {
    frequency: 'daily' | 'weekly' | 'monthly' | 'none';
    until?: Date;
  };

  @IsEnum(['pending', 'in-progress', 'completed'])
  @IsOptional()
  status?: string;

  @IsArray()
  @IsDate({ each: true })
  @IsOptional()
  reminders?: Date[];
}
