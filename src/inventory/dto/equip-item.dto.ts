import { IsNotEmpty, IsString } from 'class-validator';

export class EquipItemDto {
  @IsNotEmpty()
  @IsString()
  inventoryId: string; // ID của bản ghi trong UserInventory, không phải ID vật phẩm
}
