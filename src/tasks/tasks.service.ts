import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Task, TaskDocument } from './task.schema';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';

@Injectable()
export class TasksService {
  constructor(@InjectModel(Task.name) private taskModel: Model<TaskDocument>) {}

  async create(
    createTaskDto: CreateTaskDto,
    userId: string,
  ): Promise<TaskDocument> {
    const task = await this.taskModel.create({
      ...createTaskDto,
      userId,
    });
    return task;
  }

  async findAll(userId: string): Promise<TaskDocument[]> {
    return this.taskModel.find({ userId }).exec();
  }
}
