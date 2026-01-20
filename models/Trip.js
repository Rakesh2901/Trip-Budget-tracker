const mongoose = require('mongoose');

const ExpenseSchema = new mongoose.Schema({
  description: { type: String, required: true },
  amount: { type: Number, required: true },
  category: { 
    type: String, 
    enum: ['Lodging', 'Transportation', 'Food', 'Entertainment', 'Insurance', 'Other'],
    default: 'Other'
  },
  date: { type: Date, default: Date.now }
});

const TripSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // <--- LINK TO USER
  destination: { type: String, required: true },
  budget: { type: Number, required: true },
  startDate: { type: Date },
  expenses: [ExpenseSchema]
});

module.exports = mongoose.model('Trip', TripSchema);