// File: src/payments/payments.controller.ts

import {
  Controller,
  Post,
  Body,
  UseGuards,
  Headers,
  Req,
  Patch,
  Get, // Import Get
  Param, // Import Param
  Res, // Import Res
} from '@nestjs/common';
import { PaymentsService } from './payments.service';
import { CreatePaymentDto } from './dto/create-payment.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { GetUser } from '../auth/decorators/get-user.decorator';
import { UserDocument } from '../auth/schemas/user.schema';
import { FulfillPaymentDto } from './dto/fulfill-payment.dto';
import { Response } from 'express'; // Import Response from express

@Controller('payments')
export class PaymentsController {
  constructor(private readonly paymentsService: PaymentsService) {}
  @UseGuards(JwtAuthGuard)
  @Post('create-payment-intent')
  createPaymentIntent(
    @GetUser() user: UserDocument,
    @Body() createPaymentDto: CreatePaymentDto,
  ) {
    return this.paymentsService.createPaymentIntent(
      user,
      createPaymentDto.packageId,
    );
  }

  @UseGuards(JwtAuthGuard)
  @Patch('fulfill-payment')
  async fulfillPayment(@Body() fulfillPaymentDto: FulfillPaymentDto) {
    const result = await this.paymentsService.fulfillOrder(
      fulfillPaymentDto.paymentIntentId,
    );
    return {
      message: result.message,
      orderId: result.orderId, // Thêm orderId vào phản hồi
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('receipt/:orderId')
  async getReceipt(@Param('orderId') orderId: string, @Res() res: Response) {
    const filePath = await this.paymentsService.getReceiptPath(orderId);
    res.download(filePath);
  }

  @Post('webhook')
  handleWebhook(
    @Req() req: any,
    @Headers('stripe-signature') signature: string,
  ) {
    return this.paymentsService.handleWebhookEvent(req.rawBody, signature);
  }

  // Thêm endpoint admin

  @UseGuards(JwtAuthGuard) // Thay thế bằng AdminGuard nếu bạn có
  @Get('transactions')
  getAllTransactions() {
    return this.paymentsService.getAllTransactions();
  }
}
