import { Test, TestingModule } from '@nestjs/testing';
import { GameActivityController } from './game-activity.controller';

describe('GameActivityController', () => {
  let controller: GameActivityController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [GameActivityController],
    }).compile();

    controller = module.get<GameActivityController>(GameActivityController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
