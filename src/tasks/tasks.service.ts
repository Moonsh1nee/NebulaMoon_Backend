import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { FilterQuery, Model } from 'mongoose';
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

  async findAll(userId: string, filters?: any): Promise<TaskDocument[]> {
    const query: FilterQuery<TaskDocument> = { userId };

    console.log(filters?.status);

    if (filters?.status) query.status = filters.status;
    if (filters?.priority) query.priority = filters.priority;
    if (filters?.tags) query.tags = { $in: filters.tags.split(',') };
    if (filters?.search) query.title = { $regex: filters.search, $options: 'i' };

    return this.taskModel.find(query).exec();
  }
}
