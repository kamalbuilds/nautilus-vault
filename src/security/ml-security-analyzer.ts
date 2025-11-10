/**
 * Machine Learning Security Analyzer
 * Advanced ML-based threat detection and analysis
 */

import { MLModel, SecurityError } from '../types';
import { Matrix } from 'ml-matrix';
import { LinearRegression, LogisticRegression } from 'ml-regression';

export interface MLPrediction {
  isFraud: boolean;
  score: number;
  confidence: number;
  modelUsed: string;
  features: number[];
}

export interface AnomalyResult {
  isAnomaly: boolean;
  anomalyScore: number;
  threshold: number;
  features: number[];
}

export interface ModelTrainingData {
  features: number[][];
  labels: number[];
  weights?: number[];
}

export class MLSecurityAnalyzer {
  private fraudDetectionModel: LogisticRegression | null = null;
  private anomalyDetectionModel: any = null;
  private clusteringModel: any = null;
  private models: Map<string, MLModel> = new Map();
  private featureScalers: Map<string, any> = new Map();
  private trainingData: Map<string, ModelTrainingData> = new Map();

  constructor() {
    this.initializeModels();
  }

  /**
   * Initialize ML models
   */
  private async initializeModels(): Promise<void> {
    try {
      // Initialize fraud detection model
      await this.initializeFraudDetectionModel();

      // Initialize anomaly detection model
      await this.initializeAnomalyDetectionModel();

      // Initialize clustering model for behavioral analysis
      await this.initializeClusteringModel();

      console.log('ML Security Analyzer initialized successfully');
    } catch (error) {
      throw new SecurityError('Failed to initialize ML models', 'ML_INIT_ERROR', 'HIGH');
    }
  }

  /**
   * Predict fraud probability using ML model
   */
  async predictFraud(features: number[]): Promise<MLPrediction> {
    try {
      if (!this.fraudDetectionModel) {
        throw new SecurityError('Fraud detection model not initialized', 'MODEL_NOT_INITIALIZED', 'HIGH');
      }

      // Normalize features
      const normalizedFeatures = this.normalizeFeatures(features, 'fraud');

      // Make prediction
      const prediction = this.fraudDetectionModel.predict(normalizedFeatures);
      const probability = this.sigmoidActivation(prediction);

      // Calculate confidence based on distance from decision boundary
      const confidence = Math.abs(probability - 0.5) * 2;

      return {
        isFraud: probability > 0.5,
        score: probability,
        confidence,
        modelUsed: 'logistic_regression',
        features: normalizedFeatures
      };

    } catch (error) {
      throw new SecurityError(`Fraud prediction failed: ${error.message}`, 'PREDICTION_ERROR', 'HIGH');
    }
  }

  /**
   * Detect anomalies in behavior patterns
   */
  async detectAnomalies(features: number[]): Promise<AnomalyResult> {
    try {
      // Normalize features
      const normalizedFeatures = this.normalizeFeatures(features, 'anomaly');

      // Calculate anomaly score using isolation forest approach
      const anomalyScore = this.calculateAnomalyScore(normalizedFeatures);

      // Dynamic threshold based on recent data
      const threshold = this.calculateDynamicThreshold('anomaly');

      return {
        isAnomaly: anomalyScore > threshold,
        anomalyScore,
        threshold,
        features: normalizedFeatures
      };

    } catch (error) {
      throw new SecurityError(`Anomaly detection failed: ${error.message}`, 'ANOMALY_DETECTION_ERROR', 'HIGH');
    }
  }

  /**
   * Cluster user behaviors for pattern analysis
   */
  async clusterBehaviors(behaviorData: number[][]): Promise<any[]> {
    try {
      // Normalize behavior data
      const normalizedData = behaviorData.map(features =>
        this.normalizeFeatures(features, 'clustering')
      );

      // Perform K-means clustering
      const clusters = await this.performKMeansClustering(normalizedData, 5);

      return clusters;

    } catch (error) {
      throw new SecurityError(`Behavior clustering failed: ${error.message}`, 'CLUSTERING_ERROR', 'HIGH');
    }
  }

  /**
   * Train fraud detection model with new data
   */
  async trainFraudModel(trainingData: ModelTrainingData): Promise<void> {
    try {
      // Store training data
      this.trainingData.set('fraud', trainingData);

      // Prepare data
      const features = new Matrix(trainingData.features);
      const labels = trainingData.labels;

      // Normalize features
      const normalizedFeatures = this.normalizeFeatureMatrix(features, 'fraud');

      // Train logistic regression model
      this.fraudDetectionModel = new LogisticRegression(
        normalizedFeatures.to2DArray(),
        labels,
        {
          numSteps: 1000,
          learningRate: 0.01,
          regularization: 0.1
        }
      );

      // Update model metadata
      this.updateModelMetadata('fraud', 'logistic_regression', trainingData);

      console.log('Fraud detection model trained successfully');

    } catch (error) {
      throw new SecurityError(`Model training failed: ${error.message}`, 'TRAINING_ERROR', 'HIGH');
    }
  }

  /**
   * Train anomaly detection model
   */
  async trainAnomalyModel(normalData: number[][]): Promise<void> {
    try {
      // Store normal behavior patterns
      this.trainingData.set('anomaly', {
        features: normalData,
        labels: new Array(normalData.length).fill(0) // All normal
      });

      // Calculate statistics for normal behavior
      const stats = this.calculateStatistics(normalData);

      // Store anomaly detection parameters
      this.anomalyDetectionModel = {
        mean: stats.mean,
        std: stats.std,
        covariance: stats.covariance,
        threshold: stats.threshold
      };

      console.log('Anomaly detection model trained successfully');

    } catch (error) {
      throw new SecurityError(`Anomaly model training failed: ${error.message}`, 'ANOMALY_TRAINING_ERROR', 'HIGH');
    }
  }

  /**
   * Evaluate model performance
   */
  async evaluateModel(modelType: string, testData: ModelTrainingData): Promise<any> {
    try {
      const results = {
        accuracy: 0,
        precision: 0,
        recall: 0,
        f1Score: 0,
        confusionMatrix: [[0, 0], [0, 0]]
      };

      if (modelType === 'fraud' && this.fraudDetectionModel) {
        return this.evaluateFraudModel(testData);
      } else if (modelType === 'anomaly' && this.anomalyDetectionModel) {
        return this.evaluateAnomalyModel(testData);
      }

      return results;

    } catch (error) {
      throw new SecurityError(`Model evaluation failed: ${error.message}`, 'EVALUATION_ERROR', 'MEDIUM');
    }
  }

  /**
   * Update model with new training data (online learning)
   */
  async updateModel(modelType: string, newData: ModelTrainingData): Promise<void> {
    try {
      const existingData = this.trainingData.get(modelType);
      if (!existingData) {
        throw new SecurityError('No existing training data found', 'NO_TRAINING_DATA', 'MEDIUM');
      }

      // Combine existing and new data
      const combinedData: ModelTrainingData = {
        features: [...existingData.features, ...newData.features],
        labels: [...existingData.labels, ...newData.labels]
      };

      // Limit data size to prevent memory issues
      const maxSamples = 10000;
      if (combinedData.features.length > maxSamples) {
        combinedData.features = combinedData.features.slice(-maxSamples);
        combinedData.labels = combinedData.labels.slice(-maxSamples);
      }

      // Retrain model
      if (modelType === 'fraud') {
        await this.trainFraudModel(combinedData);
      } else if (modelType === 'anomaly') {
        await this.trainAnomalyModel(combinedData.features);
      }

      console.log(`${modelType} model updated successfully`);

    } catch (error) {
      throw new SecurityError(`Model update failed: ${error.message}`, 'UPDATE_ERROR', 'MEDIUM');
    }
  }

  /**
   * Get model information
   */
  getModelInfo(modelType: string): MLModel | null {
    return this.models.get(modelType) || null;
  }

  /**
   * Export trained model
   */
  exportModel(modelType: string): any {
    try {
      if (modelType === 'fraud' && this.fraudDetectionModel) {
        return {
          type: 'logistic_regression',
          weights: this.fraudDetectionModel.weights,
          bias: this.fraudDetectionModel.bias,
          scaler: this.featureScalers.get('fraud')
        };
      } else if (modelType === 'anomaly' && this.anomalyDetectionModel) {
        return this.anomalyDetectionModel;
      }

      return null;
    } catch (error) {
      throw new SecurityError(`Model export failed: ${error.message}`, 'EXPORT_ERROR', 'MEDIUM');
    }
  }

  /**
   * Import pre-trained model
   */
  importModel(modelType: string, modelData: any): void {
    try {
      if (modelType === 'fraud') {
        // Recreate logistic regression model
        this.fraudDetectionModel = {
          weights: modelData.weights,
          bias: modelData.bias,
          predict: (features: number[]) => {
            const dotProduct = features.reduce((sum, f, i) =>
              sum + f * modelData.weights[i], 0) + modelData.bias;
            return dotProduct;
          }
        } as LogisticRegression;

        this.featureScalers.set('fraud', modelData.scaler);
      } else if (modelType === 'anomaly') {
        this.anomalyDetectionModel = modelData;
      }

      console.log(`${modelType} model imported successfully`);

    } catch (error) {
      throw new SecurityError(`Model import failed: ${error.message}`, 'IMPORT_ERROR', 'MEDIUM');
    }
  }

  // Private helper methods

  private async initializeFraudDetectionModel(): Promise<void> {
    // Initialize with synthetic training data
    const syntheticData = this.generateSyntheticFraudData();
    await this.trainFraudModel(syntheticData);
  }

  private async initializeAnomalyDetectionModel(): Promise<void> {
    // Initialize with synthetic normal behavior data
    const normalData = this.generateSyntheticNormalData();
    await this.trainAnomalyModel(normalData);
  }

  private async initializeClusteringModel(): Promise<void> {
    // Initialize clustering model
    this.clusteringModel = {
      numClusters: 5,
      centroids: [],
      initialized: false
    };
  }

  private generateSyntheticFraudData(): ModelTrainingData {
    const features: number[][] = [];
    const labels: number[] = [];

    // Generate normal transactions
    for (let i = 0; i < 800; i++) {
      features.push([
        Math.random() * 24, // hour
        Math.random() * 7,  // day of week
        Math.random() * 1000 + 50, // amount (50-1050)
        Math.random() * 0.3, // network risk (low)
        Math.random() * 3600 + 300 // session duration (5-65 minutes)
      ]);
      labels.push(0); // Normal
    }

    // Generate fraudulent transactions
    for (let i = 0; i < 200; i++) {
      features.push([
        Math.random() * 6 + 22, // late hours (10 PM - 4 AM)
        Math.random() * 7,
        Math.random() * 5000 + 2000, // large amounts
        Math.random() * 0.7 + 0.3, // high network risk
        Math.random() * 60 // short sessions
      ]);
      labels.push(1); // Fraud
    }

    return { features, labels };
  }

  private generateSyntheticNormalData(): number[][] {
    const data: number[][] = [];

    for (let i = 0; i < 1000; i++) {
      data.push([
        Math.random() * 16 + 6, // business hours (6 AM - 10 PM)
        Math.random() * 5 + 1,  // weekdays
        Math.random() * 500 + 10, // normal amounts
        Math.random() * 0.2,    // low network risk
        Math.random() * 1800 + 900 // normal sessions (15-45 minutes)
      ]);
    }

    return data;
  }

  private normalizeFeatures(features: number[], modelType: string): number[] {
    let scaler = this.featureScalers.get(modelType);

    if (!scaler) {
      // Create new scaler based on training data
      scaler = this.createFeatureScaler(modelType);
      this.featureScalers.set(modelType, scaler);
    }

    return features.map((value, index) => {
      const mean = scaler.means[index];
      const std = scaler.stds[index];
      return std > 0 ? (value - mean) / std : 0;
    });
  }

  private normalizeFeatureMatrix(matrix: Matrix, modelType: string): Matrix {
    const normalized = matrix.clone();
    const scaler = this.createFeatureScalerFromMatrix(matrix);
    this.featureScalers.set(modelType, scaler);

    for (let i = 0; i < matrix.rows; i++) {
      for (let j = 0; j < matrix.columns; j++) {
        const value = matrix.get(i, j);
        const mean = scaler.means[j];
        const std = scaler.stds[j];
        normalized.set(i, j, std > 0 ? (value - mean) / std : 0);
      }
    }

    return normalized;
  }

  private createFeatureScaler(modelType: string): any {
    const trainingData = this.trainingData.get(modelType);
    if (!trainingData) {
      throw new SecurityError('No training data available for scaler', 'NO_TRAINING_DATA', 'MEDIUM');
    }

    const matrix = new Matrix(trainingData.features);
    return this.createFeatureScalerFromMatrix(matrix);
  }

  private createFeatureScalerFromMatrix(matrix: Matrix): any {
    const means: number[] = [];
    const stds: number[] = [];

    for (let j = 0; j < matrix.columns; j++) {
      const column = matrix.getColumn(j);
      const mean = column.reduce((sum, val) => sum + val, 0) / column.length;
      const variance = column.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / column.length;
      const std = Math.sqrt(variance);

      means.push(mean);
      stds.push(std);
    }

    return { means, stds };
  }

  private sigmoidActivation(x: number): number {
    return 1 / (1 + Math.exp(-x));
  }

  private calculateAnomalyScore(features: number[]): number {
    if (!this.anomalyDetectionModel) {
      return 0;
    }

    // Calculate Mahalanobis distance
    const mean = this.anomalyDetectionModel.mean;
    const covariance = this.anomalyDetectionModel.covariance;

    let distance = 0;
    for (let i = 0; i < features.length; i++) {
      for (let j = 0; j < features.length; j++) {
        distance += (features[i] - mean[i]) * covariance[i][j] * (features[j] - mean[j]);
      }
    }

    return Math.sqrt(Math.abs(distance));
  }

  private calculateDynamicThreshold(modelType: string): number {
    // Simple dynamic threshold based on recent scores
    return modelType === 'anomaly' ? 2.5 : 0.7;
  }

  private calculateStatistics(data: number[][]): any {
    const matrix = new Matrix(data);
    const mean = [];
    const std = [];
    const covariance = [];

    // Calculate means and standard deviations
    for (let j = 0; j < matrix.columns; j++) {
      const column = matrix.getColumn(j);
      const columnMean = column.reduce((sum, val) => sum + val, 0) / column.length;
      const columnVar = column.reduce((sum, val) => sum + Math.pow(val - columnMean, 2), 0) / column.length;

      mean.push(columnMean);
      std.push(Math.sqrt(columnVar));
    }

    // Calculate covariance matrix (simplified)
    for (let i = 0; i < matrix.columns; i++) {
      covariance[i] = [];
      for (let j = 0; j < matrix.columns; j++) {
        if (i === j) {
          covariance[i][j] = 1 / (std[i] * std[i] || 1);
        } else {
          covariance[i][j] = 0;
        }
      }
    }

    return {
      mean,
      std,
      covariance,
      threshold: 2.5 // Default threshold for anomaly detection
    };
  }

  private async performKMeansClustering(data: number[][], k: number): Promise<any[]> {
    // Simplified K-means implementation
    const centroids = this.initializeCentroids(data, k);
    const clusters = new Array(k).fill(null).map(() => []);

    for (let iteration = 0; iteration < 100; iteration++) {
      // Assign points to clusters
      clusters.forEach(cluster => cluster.length = 0);

      for (const point of data) {
        let minDistance = Infinity;
        let nearestCluster = 0;

        for (let i = 0; i < centroids.length; i++) {
          const distance = this.euclideanDistance(point, centroids[i]);
          if (distance < minDistance) {
            minDistance = distance;
            nearestCluster = i;
          }
        }

        clusters[nearestCluster].push(point);
      }

      // Update centroids
      const newCentroids = centroids.map((_, i) => {
        if (clusters[i].length === 0) return centroids[i];

        const dimensions = clusters[i][0].length;
        const newCentroid = new Array(dimensions).fill(0);

        for (const point of clusters[i]) {
          for (let j = 0; j < dimensions; j++) {
            newCentroid[j] += point[j];
          }
        }

        return newCentroid.map(sum => sum / clusters[i].length);
      });

      // Check for convergence
      let converged = true;
      for (let i = 0; i < centroids.length; i++) {
        if (this.euclideanDistance(centroids[i], newCentroids[i]) > 0.001) {
          converged = false;
          break;
        }
      }

      centroids.splice(0, centroids.length, ...newCentroids);

      if (converged) break;
    }

    return clusters.map((cluster, index) => ({
      centroid: centroids[index],
      points: cluster,
      size: cluster.length
    }));
  }

  private initializeCentroids(data: number[][], k: number): number[][] {
    const centroids = [];
    const dimensions = data[0].length;

    for (let i = 0; i < k; i++) {
      const centroid = [];
      for (let j = 0; j < dimensions; j++) {
        const min = Math.min(...data.map(point => point[j]));
        const max = Math.max(...data.map(point => point[j]));
        centroid.push(Math.random() * (max - min) + min);
      }
      centroids.push(centroid);
    }

    return centroids;
  }

  private euclideanDistance(point1: number[], point2: number[]): number {
    return Math.sqrt(
      point1.reduce((sum, val, i) => sum + Math.pow(val - point2[i], 2), 0)
    );
  }

  private evaluateFraudModel(testData: ModelTrainingData): any {
    let tp = 0, fp = 0, tn = 0, fn = 0;

    for (let i = 0; i < testData.features.length; i++) {
      const prediction = this.predictFraud(testData.features[i]);
      const predicted = prediction.isFraud ? 1 : 0;
      const actual = testData.labels[i];

      if (predicted === 1 && actual === 1) tp++;
      else if (predicted === 1 && actual === 0) fp++;
      else if (predicted === 0 && actual === 0) tn++;
      else if (predicted === 0 && actual === 1) fn++;
    }

    const accuracy = (tp + tn) / (tp + fp + tn + fn);
    const precision = tp / (tp + fp) || 0;
    const recall = tp / (tp + fn) || 0;
    const f1Score = 2 * (precision * recall) / (precision + recall) || 0;

    return {
      accuracy,
      precision,
      recall,
      f1Score,
      confusionMatrix: [[tn, fp], [fn, tp]]
    };
  }

  private evaluateAnomalyModel(testData: ModelTrainingData): any {
    let tp = 0, fp = 0, tn = 0, fn = 0;

    for (let i = 0; i < testData.features.length; i++) {
      const result = this.detectAnomalies(testData.features[i]);
      const predicted = result.isAnomaly ? 1 : 0;
      const actual = testData.labels[i];

      if (predicted === 1 && actual === 1) tp++;
      else if (predicted === 1 && actual === 0) fp++;
      else if (predicted === 0 && actual === 0) tn++;
      else if (predicted === 0 && actual === 1) fn++;
    }

    const accuracy = (tp + tn) / (tp + fp + tn + fn);
    const precision = tp / (tp + fp) || 0;
    const recall = tp / (tp + fn) || 0;
    const f1Score = 2 * (precision * recall) / (precision + recall) || 0;

    return {
      accuracy,
      precision,
      recall,
      f1Score,
      confusionMatrix: [[tn, fp], [fn, tp]]
    };
  }

  private updateModelMetadata(modelType: string, algorithm: string, trainingData: ModelTrainingData): void {
    this.models.set(modelType, {
      id: `${modelType}_${Date.now()}`,
      type: algorithm.includes('classification') ? 'CLASSIFICATION' : 'ANOMALY_DETECTION',
      version: '1.0.0',
      accuracy: 0.85, // Would be calculated from validation
      lastTrained: new Date()
    });
  }
}