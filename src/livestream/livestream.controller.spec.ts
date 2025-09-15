import { Test, TestingModule } from '@nestjs/testing';
import { LivestreamController } from './livestream.controller';

describe('LivestreamController', () => {
  let controller: LivestreamController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [LivestreamController],
    }).compile();

    controller = module.get<LivestreamController>(LivestreamController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
