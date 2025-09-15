import {
  Injectable,
  NotFoundException,
  InternalServerErrorException,
  BadRequestException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model, Types } from 'mongoose';
import { Order, OrderDocument, OrderStatus } from './schemas/order.schema';
import { UserDocument } from '../auth/schemas/user.schema';
import {
  CoinPackage,
  CoinPackageDocument,
} from './schemas/coin-package.schema';
import { ConfigService } from '@nestjs/config';
import Stripe from 'stripe';
import { EventEmitter2 } from '@nestjs/event-emitter';
import * as PDFDocument from 'pdfkit';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class PaymentsService {
  private stripe: Stripe;

  constructor(
    @InjectModel(Order.name) private orderModel: Model<OrderDocument>,
    @InjectModel('User') private readonly userModel: Model<UserDocument>,
    @InjectModel(CoinPackage.name)
    private coinPackageModel: Model<CoinPackageDocument>,
    private configService: ConfigService,
    private eventEmitter: EventEmitter2,
  ) {
    const stripeSecretKey = this.configService.get<string>('STRIPE_SECRET_KEY');
    if (!stripeSecretKey) {
      throw new Error('STRIPE_SECRET_KEY is not defined in configuration');
    }
    this.stripe = new Stripe(stripeSecretKey, {
      apiVersion: '2024-06-20' as any,
    });
  }

  async createPaymentIntent(
    user: UserDocument,
    packageId: string,
  ): Promise<{ orderId: string; clientSecret: string }> {
    const coinPackage = await this.coinPackageModel.findOne({ packageId });
    if (!coinPackage) {
      throw new NotFoundException('Coin package not found.');
    }

    const amountInCents = Math.round(coinPackage.price * 100);

    try {
      const paymentIntent = await this.stripe.paymentIntents.create({
        amount: amountInCents,
        currency: coinPackage.currency.toLowerCase(),
        metadata: {
          userId: user._id.toString(),
          packageId: coinPackage.packageId,
        },
        automatic_payment_methods: {
          enabled: true,
        },
      });

      if (!paymentIntent.client_secret) {
        throw new InternalServerErrorException(
          'Failed to create payment intent.',
        );
      }

      const newOrder = new this.orderModel({
        user: user._id,
        coinPackage: coinPackage._id,
        amount: coinPackage.price,
        status: OrderStatus.PENDING,
        paymentIntentId: paymentIntent.id,
      });

      const savedOrder = await newOrder.save();

      return {
        orderId: (savedOrder._id as Types.ObjectId).toString(),
        clientSecret: paymentIntent.client_secret,
      };
    } catch (error) {
      throw new InternalServerErrorException(
        `Failed to create payment intent: ${error.message}`,
      );
    }
  }

  async handleWebhookEvent(payload: Buffer, signature: string) {
    const webhookSecret = this.configService.get<string>(
      'STRIPE_WEBHOOK_SECRET',
    );

    if (!webhookSecret) {
      throw new InternalServerErrorException('Webhook secret not configured');
    }

    let event: Stripe.Event;

    try {
      event = this.stripe.webhooks.constructEvent(
        payload,
        signature,
        webhookSecret,
      );
    } catch (err) {
      throw new BadRequestException(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'payment_intent.succeeded') {
      const paymentIntent = event.data.object as Stripe.PaymentIntent;
      // Note: This method call is now duplicated in the new client-driven flow
      // To avoid this, you would remove this block and rely solely on the new endpoint.
      await this.fulfillOrder(paymentIntent.id);
    }

    return { received: true };
  }
  async fulfillOrder(
    paymentIntentId: string,
  ): Promise<{ message: string; orderId: string }> {
    const paymentIntent =
      await this.stripe.paymentIntents.retrieve(paymentIntentId);

    if (paymentIntent.status !== 'succeeded') {
      throw new BadRequestException('Payment intent has not succeeded.');
    }

    const order = await this.orderModel
      .findOne({ paymentIntentId })
      .populate('coinPackage')
      .populate('user', 'username email');

    if (!order || order.status !== OrderStatus.PENDING) {
      throw new NotFoundException('Invalid order or already processed.');
    }

    const coinPackage = order.coinPackage as CoinPackageDocument;
    const user = order.user as UserDocument;

    await this.userModel.findByIdAndUpdate(
      order.user,
      { $inc: { coins: coinPackage.coinsAmount } },
      { new: true },
    );

    order.status = OrderStatus.COMPLETED;
    await order.save();

    const pdfPath = await this.generateReceiptPDF(order, user, coinPackage);

    this.eventEmitter.emit('notification.create', {
      recipientId: user._id.toString(),
      type: 'PAYMENT_SUCCESS',
      link: `/transactions/receipt/${order._id}`,
      metadata: {
        orderId: order._id,
        amount: coinPackage.price,
        coins: coinPackage.coinsAmount,
        pdfPath,
      },
    });

    return {
      message: `Successfully added ${coinPackage.coinsAmount} coins!`,
      orderId: (order._id as Types.ObjectId).toString(),
    };
  }

  private async generateReceiptPDF(
    order: OrderDocument,
    user: UserDocument,
    coinPackage: CoinPackageDocument,
  ): Promise<string> {
    const doc = new PDFDocument();
    const uploadsDir = path.join(process.cwd(), 'uploads', 'receipts');

    // Ensure directory exists
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }

    const filename = `receipt-${order._id}.pdf`;
    const filePath = path.join(uploadsDir, filename);

    return new Promise((resolve, reject) => {
      const stream = fs.createWriteStream(filePath);
      doc.pipe(stream);

      // Add content to PDF
      doc.fontSize(20).text('Payment Receipt', 100, 100);
      doc.fontSize(12);
      doc.text(`Order ID: ${order._id}`, 100, 150);
      doc.text(`User: ${user.username} (${user.email})`, 100, 190);
      doc.text(`Package: ${coinPackage.name}`, 100, 210);
      doc.text(`Coins: ${coinPackage.coinsAmount}`, 100, 230);
      doc.text(`Amount: $${coinPackage.price}`, 100, 250);
      doc.text(`Status: ${order.status}`, 100, 270);
      doc.text(`Payment ID: ${order.paymentIntentId}`, 100, 290);

      doc.end();

      stream.on('finish', () => resolve(`/uploads/receipts/${filename}`));
      stream.on('error', reject);
    });
  }

  async getAllTransactions() {
    return this.orderModel
      .find()
      .populate('user', 'username email')
      .populate('coinPackage', 'name coinsAmount price')
      .sort({ createdAt: -1 })
      .exec();
  }

  async getTransactionsByUser(userId: string) {
    return this.orderModel
      .find({ user: userId })
      .populate('coinPackage', 'name coinsAmount price')
      .sort({ createdAt: -1 })
      .exec();
  }

  async getReceiptPath(orderId: string): Promise<string> {
    const order = await this.orderModel.findById(orderId);
    if (!order) {
      throw new NotFoundException('Order not found');
    }

    const filename = `receipt-${orderId}.pdf`;
    return path.join('uploads', 'receipts', filename);
  }

  async createCoinPackage(dto: CoinPackageDocument): Promise<CoinPackage> {
    const newPackage = new this.coinPackageModel(dto);
    return await newPackage.save();
  }
}
