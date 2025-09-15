import { IsEnum } from 'class-validator';
import { ItemType } from '../../shop/schemas/shop-item.schema';

export class UnequipItemDto {
  @IsEnum(ItemType)
  type: ItemType; 
}
