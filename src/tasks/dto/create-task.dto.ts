import {
  IsString,
  IsNotEmpty,
  IsOptional,
  IsDate,
  IsEnum,
  IsArray,
  IsObject,
  IsBoolean,
} from 'class-validator';

export class CreateTaskDto {
  @IsString()
  @IsNotEmpty()
  title: string;

  @IsString()
  @IsNotEmpty()
  userId: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsNotEmpty()
  @IsBoolean()
  completed: boolean;
}
